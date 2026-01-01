use crate::config::CacheConfig;
use moka::future::Cache;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname_lc: String,
    pub qtype: u16,
    pub do_bit: bool,
}

#[derive(Clone)]
pub struct CachedEntry {
    pub bytes: Vec<u8>,
    pub expires_at: Instant,
    pub stale_until: Instant,
}

#[derive(Clone)]
pub struct DnsCaches {
    pub answers: Cache<CacheKey, CachedEntry>,
    pub negative: Cache<CacheKey, CachedEntry>,
    pub cfg: CacheConfig,
}

impl DnsCaches {
    pub fn new(cfg: CacheConfig) -> Self {
        Self {
            answers: Cache::builder()
                .max_capacity(cfg.answer_cache_size)
                .build(),
            negative: Cache::builder()
                .max_capacity(cfg.negative_cache_size)
                .build(),
            cfg,
        }
    }

    pub fn classify(&self, entry: &CachedEntry) -> CacheState {
        let now = Instant::now();

        if now < entry.expires_at {
            let remaining = entry.expires_at - now;
            if remaining <= Duration::from_secs(self.cfg.prefetch_threshold_secs) {
                CacheState::NearExpiry
            } else {
                CacheState::Fresh
            }
        } else if now < entry.stale_until {
            CacheState::Stale
        } else {
            CacheState::Dead
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CacheState {
    Fresh,
    NearExpiry,
    Stale,
    Dead,
}

