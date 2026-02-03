//! uTURN - Single-port TURN relay server library
//!
//! This library provides a TURN server implementation that multiplexes all traffic
//! through a single UDP port using packet-level demultiplexing.

pub mod config;
pub mod demux;
pub mod lookup;
pub mod relay;
pub mod server;
pub mod transport;
pub mod turn;

pub use config::Config;
pub use server::Server;
