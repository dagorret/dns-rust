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

    let cfg_path = parse_cfg_path().unwrap_or_else(|| "config/up.toml".to_string());
    let cfg = config::AppConfig::load(&cfg_path)
        .with_context(|| format!("no pude leer config: {}", cfg_path))?;

    let zones = zones::ZoneStore::load_dir(&cfg.zones.zones_dir)
        .with_context(|| format!("no pude cargar zones desde {}", cfg.zones.zones_dir))?;

    let filters = filters::Filters::from_config(&cfg.filters)?;
    let caches = cache::DnsCaches::new(&cfg.cache);

    // --- Decidir modo ---
    // Nota: en TOML, `upstreams = []` => Some(vec![]). Eso NO debería forzar forwarder.
    // Forwarder sólo si hay upstreams efectivos.
    let upstreams = cfg.upstreams.clone().unwrap_or_default();
    let is_forwarder = !upstreams.is_empty();
    let is_recursor = !is_forwarder && !cfg.roots.is_empty();

    let handler = if is_forwarder {
        tracing::info!("Modo: FORWARDER (upstreams={:?})", upstreams);

        // build_forwarder es async: hay que await antes de usar Context.
        let resolver = forwarder::build_forwarder(&upstreams)
            .await
            .context("no pude crear forwarder")?;

        handler::DnsHandler::new(cfg, zones, filters, caches, Some(resolver), None)
    } else if is_recursor {
        tracing::info!("Modo: RECURSOR ITERATIVO (roots={})", cfg.roots.len());

        let recursor = recursor_engine::RecursorEngine::new(&cfg)
            .await
            .context("no pude crear recursor")?;

        handler::DnsHandler::new(cfg, zones, filters, caches, None, Some(recursor))
    } else {
        anyhow::bail!("roots está vacío y no hay upstreams: no puedo hacer recursión");
    };

    let udp = handler.cfg.listen_udp.parse()?;
    let tcp = handler.cfg.listen_tcp.parse()?;

    tracing::info!("Escuchando UDP {}", udp);
    tracing::info!("Escuchando TCP {}", tcp);

    handler.serve(udp, tcp).await?;
    Ok(())
}

fn parse_cfg_path() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| args.get(i + 1))
        .cloned()
}
