//! Coarse-grained timestamp for reducing syscall overhead
//!
//! Instead of calling `Instant::now()` on every packet, we cache a timestamp
//! and update it periodically. This trades precision for performance.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Resolution of the coarse timestamp in milliseconds
const UPDATE_INTERVAL_MS: u64 = 10;

/// Global coarse timestamp
static COARSE_INSTANT_MS: AtomicU64 = AtomicU64::new(0);
static BASE_INSTANT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Initialize the coarse timestamp system
/// Must be called once at startup before using `coarse_now()`
pub fn init() {
    let base = BASE_INSTANT.get_or_init(Instant::now);
    let _ = base; // Ensure initialization
    update_coarse_time();
}

/// Update the coarse timestamp (call this periodically)
pub fn update_coarse_time() {
    let base = BASE_INSTANT.get_or_init(Instant::now);
    let elapsed_ms = base.elapsed().as_millis() as u64;
    COARSE_INSTANT_MS.store(elapsed_ms, Ordering::Relaxed);
}

/// Get the current coarse timestamp in milliseconds since init
#[inline]
pub fn coarse_now_ms() -> u64 {
    COARSE_INSTANT_MS.load(Ordering::Relaxed)
}

/// Check if the given timestamp (ms since init) is older than `timeout_secs`
#[inline]
pub fn is_expired_secs(timestamp_ms: u64, timeout_secs: u64) -> bool {
    let now = coarse_now_ms();
    let timeout_ms = timeout_secs * 1000;
    now.saturating_sub(timestamp_ms) >= timeout_ms
}

/// Coarse instant wrapper that's compatible with existing code
#[derive(Debug, Clone, Copy)]
pub struct CoarseInstant {
    ms_since_init: u64,
}

impl CoarseInstant {
    /// Get the current coarse instant
    #[inline]
    pub fn now() -> Self {
        Self {
            ms_since_init: coarse_now_ms(),
        }
    }

    /// Check if this instant is older than `secs` seconds
    #[inline]
    pub fn elapsed_secs(&self) -> u64 {
        coarse_now_ms().saturating_sub(self.ms_since_init) / 1000
    }

    /// Check if more than `secs` seconds have passed
    #[inline]
    pub fn is_older_than_secs(&self, secs: u64) -> bool {
        self.elapsed_secs() >= secs
    }
}

impl Default for CoarseInstant {
    fn default() -> Self {
        Self::now()
    }
}

/// Spawn a background task to update the coarse timestamp
pub async fn spawn_updater() {
    init();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(UPDATE_INTERVAL_MS));
        loop {
            interval.tick().await;
            update_coarse_time();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_coarse_instant() {
        init();
        update_coarse_time();

        let t1 = CoarseInstant::now();
        assert_eq!(t1.elapsed_secs(), 0);
    }

    #[test]
    fn test_is_expired() {
        init();
        update_coarse_time();

        let old_time = 0u64; // Beginning of time
                             // Simulate some time passing
        std::thread::sleep(Duration::from_millis(50));
        update_coarse_time();

        // 0 seconds timeout should be expired
        assert!(is_expired_secs(old_time, 0));
    }
}
