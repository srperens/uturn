//! Network transport layer
//!
//! Currently only UDP, but structured to support TCP in the future.

mod udp;

pub use udp::UdpTransport;
