use crate::config::FiltersConfig;
use anyhow::Context;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone)]
pub struct Filters {
    allowlist_domains: Vec<String>, // sufijos en minúsculas, con punto final opcional
    blocklist_domains: Vec<String>,
    deny_nets: Vec<IpNet>,
    allow_nets: Vec<IpNet>,
}

impl Filters {
    pub fn from_config(cfg: &FiltersConfig) -> anyhow::Result<Self> {
        let mut deny_nets = Vec::new();
        for n in &cfg.deny_nets {
            deny_nets.push(n.parse::<IpNet>().with_context(|| format!("deny_nets inválida: {n}"))?);
        }
        let mut allow_nets = Vec::new();
        for n in &cfg.allow_nets {
            allow_nets.push(n.parse::<IpNet>().with_context(|| format!("allow_nets inválida: {n}"))?);
        }

        Ok(Self {
            allowlist_domains: cfg.allowlist_domains.iter().map(norm_domain).collect(),
            blocklist_domains: cfg.blocklist_domains.iter().map(norm_domain).collect(),
            deny_nets,
            allow_nets,
        })
    }

    pub fn domain_allowed(&self, qname: &str) -> bool {
        let q = norm_domain(qname);

        if !self.allowlist_domains.is_empty() {
            if !self.allowlist_domains.iter().any(|s| is_suffix(&q, s)) {
                return false;
            }
        }

        if self.blocklist_domains.iter().any(|s| is_suffix(&q, s)) {
            return false;
        }

        true
    }

    // Filtra IPs DESTINO (nameservers) - útil para anti-rebinding / hardening
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        if !self.allow_nets.is_empty() {
            if !self.allow_nets.iter().any(|n| n.contains(&ip)) {
                return false;
            }
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
    // evitar vacío
    if x.is_empty() { x = ".".to_string(); }
    x
}
