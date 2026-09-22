//! jt-identity —— JTDB 身份与节点引导服务（docs/13）。
//!
//! # 它解决什么问题
//!
//! 此前 jt-attest 与 jt-kms 已就位，但**无签发方**：attest 要验构建身份签名、
//! KMS 要验 mTLS 客户端证书，而"证书由谁签、节点如何取得第一份凭据"没有答案
//! （鸡生蛋）。本服务即该链条的起点：
//!
//! ```text
//! 管理员预登记 node_id + 一次性 token
//!   → 节点生成 SM2 密钥对、请求挑战
//!   → 节点对服务端 nonce 做持钥证明 + 报度量
//!   → Component CA 签发 90 天节点证书
//!   → 节点以该证书做 mTLS（jt-kms 侧校验）
//! ```
//!
//! # 组件职责（docs/13 §7）
//!
//! - CA 托管代理：Root/Component/User CA 的签名操作
//! - Enrollment 服务：token 校验、CSR 校验、与 jt-attest 协同签发
//! - CRL/OCSP 服务：撤销名单签发与分发
//! - 轮换协调：证书到期提醒与再认证
//!
//! **不持有业务数据密钥**（与 jt-controller 一致，docs/02 §6.1）。
//!
//! # 实现约束（实测）
//!
//! 用 `openssl` crate 但底层必须是 **Tongsuo**（`scripts/env.sh` 导出
//! `OPENSSL_DIR`）——合规主路径是 SM2/SM3 国密体系，rustls 不支持。
//! 且 **Tongsuo 的 `X509Req::verify` 对 SM2 CSR 报 "unsupported version"**，
//! 故 enrollment 用**持钥证明**（对服务端 nonce 签名）替代 CSR 自签名校验，
//! 后者还天然防重放（详见 `enrollment.rs` 模块注释）。
mod admin_bootstrap;
mod ca;
mod crl;
mod enrollment;
mod http;

use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, clap::Parser)]
#[clap(name = "jt-identity", about = "JTDB identity & node enrollment service")]
struct Args {
    #[clap(long, default_value = "127.0.0.1:7800")]
    listen: String,
    #[clap(long, default_value = "./identity-data")]
    data_dir: PathBuf,
    #[clap(long, default_value = "cluster-a")]
    cluster: String,

    /// 初始化集群 CA 树（Root → Component → User）并生成三权引导信封。
    ///
    /// 幂等：已存在则拒绝（避免覆盖已有 CA——那会让全部已签发证书失效）。
    #[clap(long)]
    init_ca: bool,

    /// 服务端证书（PEM）。与 --tls-key 成对。
    #[clap(long)]
    tls_cert: Option<PathBuf>,
    #[clap(long)]
    tls_key: Option<PathBuf>,
    /// 客户端 CA（PEM）：给出即要求客户端证书（mTLS）。
    #[clap(long)]
    client_ca: Option<PathBuf>,
    /// Bearer token（与 mTLS 构成两道独立的门）。
    #[clap(long)]
    auth_token: Option<String>,
    /// **仅开发用**：显式关闭鉴权（enrollment 端点会签发证书，故默认必须有鉴权）。
    #[clap(long)]
    insecure_no_auth: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Args = clap::Parser::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let ca_dir = args.data_dir.join("ca");

    if args.init_ca {
        init_ca_tree(&ca_dir)?;
        return Ok(());
    }

    // 加载 CA 树；缺失则提示先 init（不自动创建——静默自建 CA 会让
    // "证书由谁签"变得不可追溯，而这正是本服务要解决的问题）
    let root = ca::Ca::load(&ca_dir, ca::CaKind::Root)
        .map_err(|e| format!("load Root CA from {}: {e}. Run --init-ca first.", ca_dir.display()))?;
    let component = ca::Ca::load(&ca_dir, ca::CaKind::Component)
        .map_err(|e| format!("load Component CA: {e}"))?;
    let user = ca::Ca::load(&ca_dir, ca::CaKind::User)
        .map_err(|e| format!("load User CA: {e}"))?;

    tracing::info!(
        "loaded CA tree: root='{}', component='{}', user='{}'",
        root.subject, component.subject, user.subject
    );

    // 鉴权配置校验（与 jt-kms 同一原则：宁可起不来，不可静默无鉴权）
    let tls_cfg = http::TlsConfig {
        cert: args.tls_cert.clone(),
        key: args.tls_key.clone(),
        client_ca: args.client_ca.clone(),
    };
    let bearer = if args.insecure_no_auth {
        tracing::warn!(
            "--insecure-no-auth given: the enrollment endpoint will be reachable \
             WITHOUT authentication and can issue certificates. Development only."
        );
        None
    } else {
        http::validate_auth(&tls_cfg, args.auth_token.as_deref())
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!("configuration refused: {e}").into()
            })?;
        args.auth_token.clone()
    };

    let svc = Arc::new(http::AppState {
        enrollment: enrollment::EnrollmentService::new(component),
        cluster: args.cluster.clone(),
        bearer_token: bearer.clone(),
        require_client_cert: tls_cfg.client_ca.is_some(),
    });

    let router = http::router(svc);
    let addr: std::net::SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "jt-identity listening on {addr} (cluster={}, transport={})",
        args.cluster,
        http::describe(&tls_cfg, bearer.as_deref())
    );

    match tls_cfg.enabled() {
        true => {
            let acceptor = http::acceptor(&tls_cfg)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let l = http::TlsListener::new(listener, acceptor);
            axum::serve(
                l,
                router.into_make_service_with_connect_info::<http::ClientCertInfo>(),
            )
            .await?;
        }
        false => axum::serve(listener, router).await?,
    }
    Ok(())
}

/// 初始化 CA 树 + 三权引导信封。
fn init_ca_tree(ca_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // 幂等保护：已存在即拒绝。
    // 覆盖已有 CA 会让**全部已签发证书立即失效**（新 CA 的链验不过旧证书），
    // 那是灾难级操作，不能由一条命令静默完成。
    if ca_dir.join("root.crt").exists() {
        return Err(format!(
            "CA tree already exists at {}. Refusing to overwrite: replacing a CA \
             invalidates every certificate it issued. Remove it manually if this \
             is intentional (disaster recovery).",
            ca_dir.display()
        )
        .into());
    }

    let root = ca::Ca::generate(ca::CaKind::Root, "JTDB Cluster Root CA")?;
    let component = ca::Ca::generate(ca::CaKind::Component, "JTDB Component CA")?;
    let user = ca::Ca::generate(ca::CaKind::User, "JTDB User CA")?;
    root.save(ca_dir)?;
    component.save(ca_dir)?;
    user.save(ca_dir)?;

    println!("=== CA 树已生成 ===");
    println!("Root CA:      {}  (有效期 {} 天)", root.subject, ca::validity_days::ROOT_CA);
    println!("Component CA: {}  (有效期 {} 天)", component.subject, ca::validity_days::INTERMEDIATE_CA);
    println!("User CA:      {}  (有效期 {} 天)", user.subject, ca::validity_days::INTERMEDIATE_CA);
    println!();
    println!("**Root CA 私钥须离线保管**（docs/13 §3）：{}", ca_dir.join("root.key").display());

    // 三权引导信封（docs/13 §6）
    let envs = admin_bootstrap::bootstrap_admins("cluster-a")?;
    let env_dir = ca_dir.join("admin-envelopes");
    std::fs::create_dir_all(&env_dir)?;
    println!();
    println!("=== 三权引导信封（docs/13 §6）===");
    println!("每个信封与其口令必须**分别经独立介质**交给对应责任人；");
    println!("任何单一信封（含口令）无法解出其他角色。");
    println!();
    for (env, pw) in &envs {
        let path = env_dir.join(format!("{}.json", env.role));
        std::fs::write(&path, serde_json::to_vec_pretty(env)?)?;
        println!("  {} 信封: {}", env.role, path.display());
        println!("  {} 初始口令: {}", env.role, pw.as_str());
    }
    println!();
    println!("**首次登录强制改密**（docs/13 §6）。");
    println!("注意：KDF 参数属待评审项（docs/12 §4.5），评审后可能调整。");
    Ok(())
}
