use crate::config::AppConfig;
use anyhow::Context;
use hickory_recursor::{DnssecPolicy, Recursor, RecursorBuilder};
use hickory_recursor::resolver::config::{NameServerConfig, NameServerConfigGroup};
use hickory_proto::xfer::Protocol;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RecursorEngine {
    recursor: Arc<Recursor>,
    timeout: Duration,
    attempts: usize,
}

impl RecursorEngine {
    pub async fn new(cfg: &AppConfig) -> anyhow::Result<Self> {
        if cfg.roots.is_empty() {
            anyhow::bail!("roots está vacío y no hay upstreams: no puedo hacer recursión iterativa");
        }

        // Root hints
        let mut roots: Vec<NameServerConfig> = Vec::new();
        for ip_str in &cfg.roots {
            let ip_addr: IpAddr = ip_str
                .parse()
                .with_context(|| format!("root ip inválida: {ip_str}"))?;

            roots.push(NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, 53),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
                http_endpoint: None,
            });
        }

        let root_group = NameServerConfigGroup::from(roots);

        let mut builder: RecursorBuilder = Recursor::builder()
            .ns_cache_size(cfg.recursor.ns_cache_size)
            .record_cache_size(cfg.recursor.record_cache_size)
            .recursion_limit(Some(cfg.recursor.recursion_limit))
            .ns_recursion_limit(Some(cfg.recursor.ns_recursion_limit))
            .case_randomization(cfg.recursor.case_randomization);

        // nameserver filter (destinos)
        let allow: Vec<IpNet> = cfg
            .filters
            .allow_nets
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let deny: Vec<IpNet> = cfg
            .filters
            .deny_nets
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        builder = builder.nameserver_filter(allow.iter(), deny.iter());

        // DNSSEC policy
        builder = builder.dnssec_policy(parse_dnssec_policy(&cfg.recursor.dnssec)?);

        let recursor = builder.build(root_group)?;

        Ok(Self {
            recursor: Arc::new(recursor),
            timeout: Duration::from_millis(cfg.recursor.timeout_ms),
            attempts: cfg.recursor.attempts.max(1),
        })
    }

    pub async fn resolve(
        &self,
        qname: hickory_proto::rr::Name,
        qtype: hickory_proto::rr::RecordType,
        do_bit: bool,
    ) -> anyhow::Result<hickory_recursor::resolver::lookup::Lookup> {
        use hickory_proto::op::Query;
        use tokio::time::timeout;

        let mut last_err: Option<anyhow::Error> = None;

        for _ in 0..self.attempts {
            let q = Query::query(qname.clone(), qtype);
            let fut = self.recursor.resolve(q, Instant::now(), do_bit);

            match timeout(self.timeout, fut).await {
                Ok(Ok(lookup)) => return Ok(lookup),
                Ok(Err(e)) => last_err = Some(anyhow::anyhow!(e)),
                Err(_) => last_err = Some(anyhow::anyhow!("timeout resolviendo")),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("fallo resolviendo")))
    }
}

fn parse_dnssec_policy(s: &str) -> anyhow::Result<DnssecPolicy> {
    let x = s.trim().to_ascii_lowercase();
    match x.as_str() {
        "off" | "securityunaware" => Ok(DnssecPolicy::SecurityUnaware),
        "process" | "validationdisabled" => {
            #[cfg(feature = "dnssec")]
            {
                Ok(DnssecPolicy::ValidationDisabled)
            }
            #[cfg(not(feature = "dnssec"))]
            {
                anyhow::bail!("dnssec='process' requiere compilar con --features dnssec")
            }
        }
        "validate" | "validatewithstatickey" => {
            #[cfg(feature = "dnssec")]
            {
                Ok(DnssecPolicy::ValidateWithStaticKey { trust_anchor: None })
            }
            #[cfg(not(feature = "dnssec"))]
            {
                anyhow::bail!("dnssec='validate' requiere compilar con --features dnssec")
            }
        }
        _ => anyhow::bail!("dnssec debe ser: off | process | validate"),
    }
}
