mod config;
mod cache;
mod filters;
mod zones;
mod recursor_engine;
mod forwarder;
mod handler;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cfg_path = parse_cfg_path().unwrap_or_else(|| "config/example.toml".to_string());
    let cfg = config::AppConfig::load(&cfg_path).with_context(|| format!("no pude leer config: {cfg_path}"))?;

    let zones = zones::ZoneStore::load_dir(&cfg.zones.zones_dir)
        .with_context(|| format!("no pude cargar zones desde {}", cfg.zones.zones_dir))?;

    let filters = filters::Filters::from_config(&cfg.filters)?;
    let caches = cache::DnsCaches::new(&cfg.cache);

    let forwarder = if let Some(ups) = cfg.upstreams.clone() {
        tracing::info!("Modo: FORWARDER (upstreams={:?})", ups);
        Some(forwarder::build_forwarder(&ups).await?)
    } else {
        None
    };

    let recursor = if forwarder.is_none() {
        tracing::info!("Modo: RECURSOR ITERATIVO (roots={})", cfg.roots.len());
        Some(recursor_engine::RecursorEngine::new(&cfg).await?)
    } else {
        None
    };

    let handler = handler::DnsHandler::new(cfg, zones, filters, caches, forwarder, recursor);

    let udp = handler.cfg.listen_udp.parse()?;
    let tcp = handler.cfg.listen_tcp.parse()?;

    tracing::info!("Escuchando UDP {}", udp);
    tracing::info!("Escuchando TCP {}", tcp);

    handler.serve(udp, tcp).await?;
    Ok(())
}

fn parse_cfg_path() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == "-c" || a == "--config").and_then(|i| args.get(i + 1)).cloned()
}
