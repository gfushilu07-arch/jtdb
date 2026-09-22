//! jt-kms —— JTDB 密钥管理服务（docs/02 §6.3、ADR-013/014、docs/04 §6）。
//!
//! 安全特性：RK 分片（Shamir N-of-K unseal）、**真 mTLS**（客户端证书校验）、
//! Bearer token 鉴权、hash 链审计日志。
//!
//! 关于 mTLS：见 `tls.rs` 的模块注释——此前 `--client-ca` 只填充了一个
//! 从未被读取的字段，服务实际以明文提供且**无任何鉴权**（实测：带
//! `--auth-token` 启动后无凭据请求仍抵达业务逻辑）。现已实现真实校验，
//! 且配置不自洽时**拒绝启动**。
mod api;
mod audit;
mod keys;
mod shamir;
mod state;
mod tls;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, clap::Parser)]
#[clap(name = "jt-kms", about = "JTDB key management service")]
struct Args {
    #[clap(long, default_value = "127.0.0.1:7700")]
    listen: String,
    #[clap(long, default_value = "./kms-data")]
    data_dir: PathBuf,
    #[clap(long, default_value = "cluster-a")]
    cluster: String,
    #[clap(long, default_value = "pageserver")]
    component_scope: String,
    #[clap(long, default_value_t = 900)]
    lease_secs: u64,
    /// 打印 RK 份额并删除明文（seal 操作）
    #[clap(long)]
    dump_shares: bool,
    #[clap(long = "unseal-share")]
    unseal_shares: Vec<String>,
    #[clap(long, default_value_t = 3)]
    shamir_threshold: usize,
    #[clap(long, default_value_t = 5)]
    shamir_shares: usize,
    /// 服务端证书链（PEM）。与 --tls-key 必须成对出现。
    #[clap(long)]
    tls_cert: Option<PathBuf>,
    /// 服务端私钥（PEM）。与 --tls-cert 必须成对出现。
    #[clap(long)]
    tls_key: Option<PathBuf>,
    /// 客户端 CA（PEM）。给出即**要求**客户端提供有效证书（mTLS）。
    #[clap(long)]
    client_ca: Option<PathBuf>,
    /// Bearer token。与 --client-ca 构成两道独立的门（都配则都要过）。
    #[clap(long)]
    auth_token: Option<String>,
    /// **仅开发用**：显式关闭鉴权。
    ///
    /// 必须显式给出——因为 jt-kms 暴露 `/v1/dek/unwrap`（解出数据密钥），
    /// "默认无鉴权"是不可接受的默认值。传本参数使"我确实关掉了鉴权"成为
    /// 一次有意识的操作，而不是默认行为。
    #[clap(long)]
    insecure_no_auth: bool,
}

/// 全局应用状态（binary crate 免泛型穿透）。
pub struct App {
    pub state: state::KmsState,
    pub audit: audit::AuditJournal,
    pub auth: api::AuthConfig,
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
    let rk_path = args.data_dir.join("master.key");

    if args.dump_shares {
        return seal_operation(&rk_path, args.shamir_threshold, args.shamir_shares);
    }

    if !args.unseal_shares.is_empty() {
        unseal_operation(&rk_path, &args.unseal_shares, args.shamir_threshold)?;
    }

    std::fs::create_dir_all(&args.data_dir)?;

    // ---- 传输层安全：配置校验必须**先于**任何服务启动 ----
    let tls_cfg = tls::TlsConfig {
        cert: args.tls_cert.clone(),
        key: args.tls_key.clone(),
        client_ca: args.client_ca.clone(),
    };
    let bearer = if args.insecure_no_auth {
        None
    } else {
        args.auth_token.clone()
    };

    if args.insecure_no_auth {
        tracing::warn!(
            "--insecure-no-auth given: jt-kms will serve WITHOUT authentication. \
             This is for development only; /v1/dek/unwrap is reachable by anyone \
             who can connect to {}. NEVER use this in production.",
            args.listen
        );
    }

    if !args.insecure_no_auth {
        tls::validate(&tls_cfg, bearer.as_deref()).map_err(|e| -> Box<dyn std::error::Error> {
            // 拒绝启动而非静默降级——见 tls::validate 的说明
            format!("configuration refused: {e}").into()
        })?;
        tls::preflight(&tls_cfg).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    let acceptor = if tls_cfg.enabled() {
        Some(tls::acceptor(&tls_cfg).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?)
    } else {
        None
    };

    let app = Arc::new(App {
        state: state::KmsState::load_or_init(
            &args.data_dir, &args.cluster, &args.component_scope,
            std::time::Duration::from_secs(args.lease_secs),
        )?,
        audit: audit::AuditJournal::open(args.data_dir.join("audit.jsonl"))?,
        auth: api::AuthConfig {
            bearer_token: bearer.clone(),
            require_client_cert: tls_cfg.client_ca.is_some(),
        },
    });
    app.audit.append("system", "service.start", &args.listen, "ok")?;

    let router = api::router(app);
    let addr: SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "jt-kms listening on {addr} (cluster={}, scope={}, lease={}s, transport={})",
        args.cluster, args.component_scope, args.lease_secs,
        tls::describe(&tls_cfg, bearer.as_deref())
    );

    match acceptor {
        Some(acceptor) => {
            let listener = TlsListener::new(listener, acceptor);
            /*
             * `into_make_service_with_connect_info` + `Connected` 实现：把
             * "本连接是否带客户端证书"从 TLS 层传到请求扩展。
             *
             * 为什么需要它：axum 的 `Listener` 抽象不允许在 accept 时直接注入
             * 请求扩展，而 `IncomingStream::io()` 能拿到 TLS 流——`Connected`
             * 正是为此设计的钩子。不这样做的话，中间件无法判断证书是否存在，
             * 只能无条件信任 TLS 层（那会让纵深防御变成空话）。
             */
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<ClientCertInfo>(),
            )
            .await?;
        }
        None => axum::serve(listener, router).await?,
    }
    Ok(())
}

/// 连接级信息：本连接是否提供了客户端证书。
///
/// 由 `Connected` 从 TLS 流中提取，随后作为请求扩展出现在
/// `tls::auth_middleware` 中。
#[derive(Debug, Clone, Copy)]
pub struct ClientCertInfo {
    pub present: bool,
}

impl<'a> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'a, TlsListener>>
    for ClientCertInfo
{
    fn connect_info(
        stream: axum::serve::IncomingStream<'_, TlsListener>,
    ) -> Self {
        /*
         * TLS 层已在握手期校验证书链（acceptor 设了
         * `PEER | FAIL_IF_NO_PEER_CERT`），故能走到这里说明：客户端提供了
         * 证书且链可信，或未要求客户端证书（未配 --client-ca）。这里只如实
         * 记录事实，判定留给中间件。
         */
        let present = stream.io().ssl().peer_certificate().is_some();
        Self { present }
    }
}

/// TLS 监听器（实现 axum 的 `Listener` trait）。
///
/// 用 axum 0.8 的 `Listener` 抽象而非手写 hyper 服务循环：axum 已把
/// "accept → 握手 → 交给 router"这条链封装好，手写一遍只会引入新缺陷
/// （本项目在别处已因"自己重实现上游已有机制"踩过坑）。
///
/// 客户端证书在**握手期**校验（acceptor 里设了
/// `PEER | FAIL_IF_NO_PEER_CERT`），未提供或校验失败即握手失败、
/// 连接被丢弃——这比"握手成功后在应用层再判"更早、更难绕过。
pub struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
}

impl TlsListener {
    fn new(inner: tokio::net::TcpListener, acceptor: openssl::ssl::SslAcceptor) -> Self {
        Self { inner, acceptor: Arc::new(acceptor) }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_openssl::SslStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.inner.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let ssl = match openssl::ssl::Ssl::new(self.acceptor.context()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Ssl::new failed: {e}");
                    continue;
                }
            };
            let mut tls_stream = match tokio_openssl::SslStream::new(ssl, stream) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SslStream::new failed: {e}");
                    continue;
                }
            };
            if let Err(e) = std::pin::Pin::new(&mut tls_stream).accept().await {
                /*
                 * 握手失败——含"未提供客户端证书"与"证书链不可信"。
                 * 记 warn 而非 error：扫描器与配置错误的客户端都会走到这里，
                 * 记 error 会淹没真正的故障。
                 */
                tracing::warn!("TLS handshake with {peer} rejected: {e}");
                continue;
            }
            return (tls_stream, peer);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn seal_operation(rk_path: &PathBuf, threshold: usize, total: usize) -> Result<(), Box<dyn std::error::Error>> {
    let rk_bytes = std::fs::read(rk_path)?;
    let rk: [u8; 32] = rk_bytes.try_into().map_err(|_| "master.key must be 32 bytes")?;
    let mut rng = rand::thread_rng();
    let shares = shamir::split(&rk, threshold, total, &mut rng)?;
    println!("=== RK Shamir 份额（{threshold}-of-{total}）===");
    for s in &shares {
        println!("share[{}]: {}", s[0], b64_encode(&s[..]));
    }
    std::fs::remove_file(rk_path)?;
    println!("=== master.key 已删除；重启需集齐 {threshold} 份 unseal ===");
    Ok(())
}

fn unseal_operation(rk_path: &PathBuf, shares_hex: &[String], threshold: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut decoded = Vec::new();
    for (i, s) in shares_hex.iter().enumerate() {
        let bytes = b64_decode(s)?;
        let arr: [u8; 33] = bytes.try_into().map_err(|_| format!("share[{}] must be 33 bytes", i + 1))?;
        decoded.push(arr);
    }
    let rk = shamir::join(&decoded, threshold).map_err(|e| format!("unseal failed: {e}"))?;
    if let Some(parent) = rk_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(rk_path, rk)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(rk_path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("unsealed from {} shares", decoded.len());
    Ok(())
}

fn b64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(CHARS[(n >> 18) as usize & 63] as char);
        out.push(CHARS[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { CHARS[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { CHARS[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const REV: fn(char) -> Option<u8> = |c| match c {
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some(c as u8 - b'a' + 26),
        '0'..='9' => Some(c as u8 - b'0' + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    };
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    let mut out = Vec::new();
    for chunk in clean.chunks(4) {
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= (REV(b as char).ok_or("invalid b64")? as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Ok(out)
}
