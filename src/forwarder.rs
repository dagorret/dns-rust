use anyhow::Context;
use hickory_proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};

use std::net::SocketAddr;

pub async fn build_forwarder(upstreams: &[String]) -> anyhow::Result<TokioResolver> {

    let mut group = NameServerConfigGroup::new();

    for u in upstreams {
        let addr: SocketAddr = u.parse().with_context(|| format!("upstream inválido: {u}"))?;

        group.push(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
            http_endpoint: None,
        });

        group.push(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
            http_endpoint: None,
        });
    }

    let mut cfg = ResolverConfig::new();
    for ns in group.into_iter() {
        cfg.add_name_server(ns);
    }

    let opts = ResolverOpts::default();

    let resolver = TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

    Ok(resolver)
}


