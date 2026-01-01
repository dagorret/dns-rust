use crate::config::CacheConfig;
use moka::future::Cache;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname_lc: String,
    pub qtype: u16,
    pub do_bit: bool,
}

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub bytes: Vec<u8>,
    pub expires_at: Instant,
    pub stale_until: Instant,
}

impl CachedEntry {
    pub fn new(bytes: Vec<u8>, ttl: Duration, stale_window: Duration) -> Self {
        let now = Instant::now();
        let expires_at = now + ttl;
        let stale_until = expires_at + stale_window;
        Self {
            bytes,
            expires_at,
            stale_until,
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

#[derive(Clone)]
pub struct DnsCaches {
    pub answers: Cache<CacheKey, CachedEntry>,
    pub negative: Cache<CacheKey, CachedEntry>,

    /// Cache auxiliar para política 2-hit del negativo:
    /// 1er NXDOMAIN/NODATA: marca probe; 2do: se cachea en `negative`.
    pub negative_probe: Cache<CacheKey, u8>,

    pub min_ttl: Duration,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,

    pub prefetch_threshold: Duration,
    pub stale_window: Duration,

    pub negative_cfg: crate::config::NegativeCacheConfig,
}

impl DnsCaches {
    pub fn new(cfg: &CacheConfig) -> Self {
        let prefetch_threshold = Duration::from_secs(cfg.prefetch_threshold_secs);
        let stale_window = Duration::from_secs(cfg.stale_window_secs);

        Self {
            answers: Cache::builder().max_capacity(cfg.answer_cache_size).build(),
            negative: Cache::builder().max_capacity(cfg.negative_cache_size).build(),
            negative_probe: Cache::builder()
                .max_capacity(cfg.negative_cache_size)
                .time_to_live(Duration::from_secs(cfg.negative.probe_ttl_secs))
                .build(),
            min_ttl: Duration::from_secs(cfg.min_ttl),
            max_ttl: Duration::from_secs(cfg.max_ttl),
            negative_ttl: Duration::from_secs(cfg.negative_ttl),
            prefetch_threshold,
            stale_window,
            negative_cfg: cfg.negative.clone(),
        }
    }

    pub fn clamp_ttl(&self, ttl: Duration) -> Duration {
        ttl.clamp(self.min_ttl, self.max_ttl)
    }

    pub fn clamp_negative_ttl(&self, ttl: Duration) -> Duration {
        let min_ttl = Duration::from_secs(self.negative_cfg.min_ttl);
        let max_ttl = Duration::from_secs(self.negative_cfg.max_ttl);
        ttl.clamp(min_ttl, max_ttl)
    }

    pub fn stale_window(&self) -> Duration {
        self.stale_window
    }

    pub fn classify(&self, entry: &CachedEntry) -> CacheState {
        let now = Instant::now();

        if now < entry.expires_at {
            let remaining = entry.expires_at - now;
            if remaining <= self.prefetch_threshold {
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
