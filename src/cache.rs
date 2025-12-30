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
    // Guarda el wire-format completo de la respuesta (Message bytes)
    pub answers: Cache<CacheKey, Vec<u8>>,
    // Guarda respuestas negativas wire-format (NXDOMAIN / NODATA)
    pub negative: Cache<CacheKey, Vec<u8>>,
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,
}

impl DnsCaches {
    pub fn new(cfg: &CacheConfig) -> Self {
        let answers = Cache::builder()
            .max_capacity(cfg.answer_cache_size)
            .build();

        let negative = Cache::builder()
            .max_capacity(cfg.negative_cache_size)
            .build();

        Self {
            answers,
            negative,
            min_ttl: Duration::from_secs(cfg.min_ttl),
            max_ttl: Duration::from_secs(cfg.max_ttl),
            negative_ttl: Duration::from_secs(cfg.negative_ttl),
        }
    }

    pub fn clamp_ttl(&self, ttl: Duration) -> Duration {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }
}
