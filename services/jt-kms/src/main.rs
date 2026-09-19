//! jt-kms —— JTDB 密钥管理服务（docs/02 §6.3、ADR-013/014、docs/04 §6）。
//!
//! 安全特性：RK 分片（Shamir N-of-K unseal）、mTLS、hash 链审计日志、
//! Bearer token 鉴权。
mod api;
mod audit;
mod keys;
mod shamir;
mod state;

#[cfg(test)]
mod tests;

use clap::Parser;
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
    #[clap(long)]
    tls_cert: Option<PathBuf>,
    #[clap(long)]
    tls_key: Option<PathBuf>,
    #[clap(long)]
    client_ca: Option<PathBuf>,
    #[clap(long)]
    auth_token: Option<String>,
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
    let app = Arc::new(App {
        state: state::KmsState::load_or_init(
            &args.data_dir, &args.cluster, &args.component_scope,
            std::time::Duration::from_secs(args.lease_secs),
        )?,
        audit: audit::AuditJournal::open(args.data_dir.join("audit.jsonl"))?,
        auth: api::AuthConfig {
            bearer_token: args.auth_token.clone(),
            require_client_cert: args.client_ca.is_some(),
        },
    });
    app.audit.append("system", "service.start", &args.listen, "ok")?;

    let router = api::router(app);
    let addr: SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("jt-kms listening on {addr} (cluster={}, scope={}, lease={}s)",
        args.cluster, args.component_scope, args.lease_secs);
    axum::serve(listener, router).await?;
    Ok(())
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
