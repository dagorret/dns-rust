use crate::config::CacheConfig;
use moka::future::Cache;
use std::time::Duration;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname_lc: String,
    pub qtype: u16,
    pub do_bit: bool,
}

#[derive(Clone)]
pub struct DnsCaches {
    pub answers: Cache<CacheKey, Vec<u8>>,
    pub negative: Cache<CacheKey, Vec<u8>>,

    // Opción B: hoy puede no usarse desde lib/bin, pero lo queremos mantener (TTL policy)
    #[allow(dead_code)]
    pub min_ttl: Duration,

    #[allow(dead_code)]
    pub max_ttl: Duration,

    #[allow(dead_code)]
    pub negative_ttl: Duration,
}

impl DnsCaches {
    pub fn new(cfg: &CacheConfig) -> Self {
        Self {
            answers: Cache::builder().max_capacity(cfg.answer_cache_size).build(),
            negative: Cache::builder().max_capacity(cfg.negative_cache_size).build(),
            min_ttl: Duration::from_secs(cfg.min_ttl),
            max_ttl: Duration::from_secs(cfg.max_ttl),
            negative_ttl: Duration::from_secs(cfg.negative_ttl),
        }
    }

    // Opción B: puede no estar usado todavía, pero lo vamos a usar en caching TTL/clamping
    #[allow(dead_code)]
    pub fn clamp_ttl(&self, ttl: Duration) -> Duration {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }
}

