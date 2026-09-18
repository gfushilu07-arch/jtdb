//! jt-kms —— JTDB 密钥管理服务（docs/02 §6.3、ADR-013/014、docs/04 §6）。
//!
//! 职责：RK/KEK/DEK 层级管理、DEK 信封封装/解封、组件租约签发/续租/撤销
//! （失效矩阵）、轮换协调（journal 化状态机）、防回滚计数器持久化。
//!
//! 启动：
//! ```text
//! jt-kms --listen 127.0.0.1:7700 --data-dir /var/lib/jtdb/kms \
//!        --cluster cluster-a --component-scope pageserver [--lease-secs 900]
//! ```

mod api;
mod keys;
mod state;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, clap::Parser)]
#[clap(name = "jt-kms", about = "JTDB key management service")]
struct Args {
    /// 监听地址
    #[clap(long, default_value = "127.0.0.1:7700")]
    listen: String,
    /// 数据目录（master.key / counters.json / rotation.journal）
    #[clap(long, default_value = "./kms-data")]
    data_dir: PathBuf,
    /// 集群标识（KEK 作用域的一部分）
    #[clap(long, default_value = "cluster-a")]
    cluster: String,
    /// 组件作用域（KEK 作用域的一部分）
    #[clap(long, default_value = "pageserver")]
    component_scope: String,
    /// 租约时长（秒；ADR-013 默认 15 分钟）
    #[clap(long, default_value_t = 900)]
    lease_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Args = clap::Parser::parse();
    let state = Arc::new(state::KmsState::load_or_init(
        &args.data_dir,
        &args.cluster,
        &args.component_scope,
        Duration::from_secs(args.lease_secs),
    )?);

    let app = api::router(state);
    let addr: SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "jt-kms listening on {addr} (cluster={}, scope={}, lease={}s)",
        args.cluster,
        args.component_scope,
        args.lease_secs
    );
    axum::serve(listener, app).await?;
    Ok(())
}
