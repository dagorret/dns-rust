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
    #[serde(default)]
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

fn d_true() -> bool {
    true
}
fn d_two_hit() -> bool {
    true
}
fn d_probe_ttl() -> u64 {
    60
}
fn d_neg_min() -> u64 {
    5
}
fn d_neg_max() -> u64 {
    300
}
fn d_prefetch() -> u64 {
    10
}
fn d_stale_window() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    pub answer_cache_size: u64,
    pub negative_cache_size: u64,

    /// TTL positivo: límites (clamp).
    pub min_ttl: u64,
    pub max_ttl: u64,

    /// TTL negativo fallback (si no se puede inferir del SOA del upstream).
    pub negative_ttl: u64,

    /// Prefetch: umbral en segundos para disparar refresh antes de expirar.
    #[serde(default = "d_prefetch")]
    pub prefetch_threshold_secs: u64,

    /// Stale-While-Revalidate: ventana de tolerancia (segundos) para servir stale y revalidar.
    #[serde(default = "d_stale_window")]
    pub stale_window_secs: u64,

    /// Cache negativo "estilo Unbound" (NXDOMAIN / NODATA) con política anti-ruido.
    #[serde(default)]
    pub negative: NegativeCacheConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NegativeCacheConfig {
    /// Habilita cache negativo en general.
    #[serde(default = "d_true")]
    pub enabled: bool,

    /// Cachear NXDOMAIN (dominio inexistente).
    #[serde(default = "d_true")]
    pub cache_nxdomain: bool,

    /// Cachear NODATA (NOERROR pero sin answers para ese qtype).
    #[serde(default = "d_true")]
    #[allow(dead_code)]
    pub cache_nodata: bool,

    /// Política 2-hit: 1er hit = probe corto, 2do hit = se cachea.
    #[serde(default = "d_two_hit")]
    pub two_hit: bool,

    /// TTL del "probe" (solo aplica si two_hit = true).
    #[serde(default = "d_probe_ttl")]
    pub probe_ttl_secs: u64,

    /// Clamp del TTL negativo.
    #[serde(default = "d_neg_min")]
    pub min_ttl: u64,
    #[serde(default = "d_neg_max")]
    pub max_ttl: u64,
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
