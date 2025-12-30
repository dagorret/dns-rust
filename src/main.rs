mod config;
mod cache;
mod filters;
mod zones;
mod recursor_engine;
mod handler;

use anyhow::Context;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args.iter()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "config/example.toml".to_string());

    let cfg = config::AppConfig::load(&cfg_path)
        .with_context(|| format!("no pude leer config: {cfg_path}"))?;

    let zones = zones::ZoneStore::load_dir(&cfg.zones.zones_dir)
        .with_context(|| format!("no pude cargar zones desde {}", cfg.zones.zones_dir))?;

    let filters = filters::Filters::from_config(&cfg.filters)?;
    let cache = cache::DnsCaches::new(&cfg.cache);

    let recursor = recursor_engine::RecursorEngine::new(&cfg).await?;

    let handler = handler::DnsHandler::new(cfg, zones, filters, cache, recursor);

    let udp: SocketAddr = handler.cfg.listen_udp.parse()?;
    let tcp: SocketAddr = handler.cfg.listen_tcp.parse()?;

    tracing::info!("DNS server (recursor) escuchando UDP {}", udp);
    tracing::info!("DNS server (recursor) escuchando TCP {}", tcp);

    handler.serve(udp, tcp).await?;

    Ok(())
}
