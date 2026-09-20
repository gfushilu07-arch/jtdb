//! jt-controller —— JTDB 控制平面（docs/02 §6.1）。
//!
//! 组件注册、心跳、生命周期、Timeline/Branch、generation、配置租约。
//! **不直接持有明文数据密钥**；generation 围栏 write-ahead 落盘（防脑裂）。

use jt_controller::api;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, clap::Parser)]
#[clap(name = "jt-controller", about = "JTDB control plane")]
struct Args {
    #[clap(long, default_value = "127.0.0.1:7900")]
    listen: String,
    #[clap(long, default_value = "./controller-data")]
    data_dir: PathBuf,
    /// 心跳超时（秒）：超过则组件转 Suspect。
    #[clap(long, default_value_t = 30)]
    heartbeat_timeout: u64,
    /// 无围栏日志运行（仅测试；重启即遗忘 generation，禁止生产使用）。
    #[clap(long)]
    no_fence_journal: bool,
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

    let controller = if args.no_fence_journal {
        tracing::warn!(
            "运行于无围栏日志模式：generation 不跨重启保留，仅限测试使用"
        );
        jt_controller::Controller::new(args.heartbeat_timeout)
    } else {
        std::fs::create_dir_all(&args.data_dir)?;
        jt_controller::Controller::open(
            args.heartbeat_timeout,
            args.data_dir.join("generation.log"),
        )?
    };

    let app = Arc::new(api::AppState {
        controller: Arc::new(controller),
        auth_token: None,
        clock: Box::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }),
    });

    let router = api::router(app);
    let addr: SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        "jt-controller listening on {addr} (heartbeat_timeout={}s, fence_journal={})",
        args.heartbeat_timeout,
        !args.no_fence_journal
    );
    axum::serve(listener, router).await?;
    Ok(())
}
