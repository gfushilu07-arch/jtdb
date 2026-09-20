//! jt-audit-ingest（docs/02 §7）。

mod api;
mod store;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, clap::Parser)]
#[clap(name = "jt-audit-ingest", about = "JTDB audit ingest service")]
struct Args {
    #[clap(long, default_value = "127.0.0.1:7800")]
    listen: String,
    #[clap(long, default_value = "./audit-store")]
    data_dir: PathBuf,
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
    let store = Arc::new(store::AuditStore::open(args.data_dir.join("audit.jsonl"))?);
    let app = Arc::new(api::AppState { store });

    let router = api::router(app);
    let addr: SocketAddr = args.listen.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("jt-audit-ingest listening on {addr}");
    axum::serve(listener, router).await?;
    Ok(())
}
