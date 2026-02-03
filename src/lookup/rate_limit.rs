//! Rate limiting and quota enforcement

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Rate limiter state for an IP address
#[derive(Debug, Default)]
struct RateLimitEntry {
    /// Timestamps of recent requests (within the window)
    request_times: Vec<Instant>,
    /// Current number of active allocations
    allocation_count: u32,
}

/// Rate limiter for TURN allocation requests
pub struct RateLimiter {
    /// Per-IP state
    entries: DashMap<IpAddr, RateLimitEntry>,
    /// Maximum requests per minute (0 = unlimited)
    max_requests_per_minute: u32,
    /// Maximum allocations per IP (0 = unlimited)
    max_allocations_per_ip: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests_per_minute: u32, max_allocations_per_ip: u32) -> Self {
        Self {
            entries: DashMap::new(),
            max_requests_per_minute,
            max_allocations_per_ip,
        }
    }

    /// Check if an allocation request is allowed and reserve a slot atomically
    ///
    /// This combines check and reservation to prevent TOCTOU race conditions.
    /// Returns Ok(()) if allowed (and slot is reserved), Err with reason if rejected.
    pub fn check_allocation_request(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let now = Instant::now();

        let mut entry = self.entries.entry(ip).or_default();

        // Only track request times if rate limiting is enabled
        // This prevents unbounded memory growth when limit is 0 (unlimited)
        if self.max_requests_per_minute > 0 {
            let window = std::time::Duration::from_secs(60);

            // Clean up old request times
            entry
                .request_times
                .retain(|&t| now.duration_since(t) < window);

            // Check rate limit
            if entry.request_times.len() >= self.max_requests_per_minute as usize {
                return Err(RateLimitError::TooManyRequests);
            }

            // Record the request time
            entry.request_times.push(now);
        }

        // Check allocation quota
        if self.max_allocations_per_ip > 0 && entry.allocation_count >= self.max_allocations_per_ip
        {
            return Err(RateLimitError::QuotaExceeded);
        }

        // Reserve the allocation slot
        entry.allocation_count = entry.allocation_count.saturating_add(1);

        Ok(())
    }

    /// Record a successful allocation (no-op, reservation done in check)
    ///
    /// This is kept for API compatibility but does nothing since
    /// check_allocation_request now atomically reserves the slot.
    #[allow(dead_code)]
    pub fn record_allocation(&self, _ip: IpAddr) {
        // Reservation is now done atomically in check_allocation_request
    }

    /// Cancel a reserved allocation slot (call if allocation fails after check)
    pub fn cancel_reservation(&self, ip: IpAddr) {
        if let Some(mut entry) = self.entries.get_mut(&ip) {
            entry.allocation_count = entry.allocation_count.saturating_sub(1);
        }
    }

    /// Record an allocation being removed
    pub fn record_deallocation(&self, ip: IpAddr) {
        if let Some(mut entry) = self.entries.get_mut(&ip) {
            entry.allocation_count = entry.allocation_count.saturating_sub(1);
        }
    }

    /// Get current allocation count for an IP
    pub fn allocation_count(&self, ip: IpAddr) -> u32 {
        self.entries
            .get(&ip)
            .map(|e| e.allocation_count)
            .unwrap_or(0)
    }

    /// Cleanup old entries (call periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        // Remove entries with no allocations and no recent requests
        self.entries.retain(|_, entry| {
            entry
                .request_times
                .retain(|&t| now.duration_since(t) < window);
            entry.allocation_count > 0 || !entry.request_times.is_empty()
        });
    }
}

/// Rate limit error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    /// Too many requests in the time window
    TooManyRequests,
    /// Maximum allocations per IP exceeded
    QuotaExceeded,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::TooManyRequests => write!(f, "rate limit exceeded"),
            RateLimitError::QuotaExceeded => write!(f, "allocation quota exceeded"),
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limit() {
        let limiter = RateLimiter::new(3, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 requests should succeed
        assert!(limiter.check_allocation_request(ip).is_ok());
        assert!(limiter.check_allocation_request(ip).is_ok());
        assert!(limiter.check_allocation_request(ip).is_ok());

        // 4th request should fail
        assert_eq!(
            limiter.check_allocation_request(ip),
            Err(RateLimitError::TooManyRequests)
        );
    }

    #[test]
    fn test_allocation_quota() {
        let limiter = RateLimiter::new(100, 2);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Allow first two allocations (check_allocation_request now reserves atomically)
        assert!(limiter.check_allocation_request(ip).is_ok());
        assert!(limiter.check_allocation_request(ip).is_ok());

        // Third should fail due to quota
        assert_eq!(
            limiter.check_allocation_request(ip),
            Err(RateLimitError::QuotaExceeded)
        );

        // After deallocation, should work again
        limiter.record_deallocation(ip);
        assert!(limiter.check_allocation_request(ip).is_ok());
    }

    #[test]
    fn test_cancel_reservation() {
        let limiter = RateLimiter::new(100, 2);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Reserve two slots
        assert!(limiter.check_allocation_request(ip).is_ok());
        assert!(limiter.check_allocation_request(ip).is_ok());

        // Third should fail
        assert_eq!(
            limiter.check_allocation_request(ip),
            Err(RateLimitError::QuotaExceeded)
        );

        // Cancel one reservation
        limiter.cancel_reservation(ip);

        // Now third should succeed
        assert!(limiter.check_allocation_request(ip).is_ok());
    }
}
