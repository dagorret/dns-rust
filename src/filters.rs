use crate::config::FiltersConfig;
use anyhow::Context;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone)]
pub struct Filters {
    allowlist_domains: Vec<String>,
    blocklist_domains: Vec<String>,

    // Opción B: puede no usarse todavía desde lib/bin, pero lo mantenemos
    #[allow(dead_code)]
    deny_nets: Vec<IpNet>,

    #[allow(dead_code)]
    allow_nets: Vec<IpNet>,
}

impl Filters {
    pub fn from_config(cfg: &FiltersConfig) -> anyhow::Result<Self> {
        let deny_nets = cfg
            .deny_nets
            .iter()
            .map(|n| n.parse::<IpNet>().with_context(|| format!("deny_nets inválida: {n}")))
            .collect::<Result<Vec<_>, _>>()?;

        let allow_nets = cfg
            .allow_nets
            .iter()
            .map(|n| n.parse::<IpNet>().with_context(|| format!("allow_nets inválida: {n}")))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            allowlist_domains: cfg.allowlist_domains.iter().map(|s| norm_domain(s)).collect(),
            blocklist_domains: cfg.blocklist_domains.iter().map(|s| norm_domain(s)).collect(),
            deny_nets,
            allow_nets,
        })
    }

    pub fn domain_allowed(&self, qname: &str) -> bool {
        let q = norm_domain(qname);

        if !self.allowlist_domains.is_empty()
            && !self.allowlist_domains.iter().any(|s| is_suffix(&q, s))
        {
            return false;
        }
        if self.blocklist_domains.iter().any(|s| is_suffix(&q, s)) {
            return false;
        }
        true
    }

    // Opción B: por ahora puede no usarse
    #[allow(dead_code)]
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        if !self.allow_nets.is_empty() && !self.allow_nets.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        if self.deny_nets.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        true
    }
}

fn is_suffix(q: &str, suffix: &str) -> bool {
    q == suffix || q.ends_with(&format!(".{suffix}"))
}

fn norm_domain(s: &str) -> String {
    let mut x = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if x.is_empty() {
        x = ".".to_string();
    }
    x
}
