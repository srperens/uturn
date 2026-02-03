//! Fast lookup tables for packet routing

mod rate_limit;
mod table;

pub use rate_limit::{RateLimitError, RateLimiter};
pub use table::{AllocationId, AllocationTable};
