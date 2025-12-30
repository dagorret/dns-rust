use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub listen_udp: String,
    pub listen_tcp: String,

    #[serde(default)]
    pub upstreams: Option<Vec<String>>,

    #[serde(default)]
    pub roots: Vec<String>,

    pub zones: ZonesConfig,
    pub filters: FiltersConfig,
    pub cache: CacheConfig,
    pub recursor: RecursorConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZonesConfig {
    pub zones_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiltersConfig {
    #[serde(default)]
    pub allowlist_domains: Vec<String>,
    #[serde(default)]
    pub blocklist_domains: Vec<String>,
    #[serde(default)]
    pub deny_nets: Vec<String>,
    #[serde(default)]
    pub allow_nets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    pub answer_cache_size: u64,
    pub negative_cache_size: u64,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub negative_ttl: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RecursorConfig {
    pub ns_cache_size: usize,
    pub record_cache_size: usize,
    pub recursion_limit: u8,
    pub ns_recursion_limit: u8,
    pub timeout_ms: u64,
    pub attempts: usize,
    pub case_randomization: bool,
    pub dnssec: String,
}

impl AppConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&s)?)
    }
}
