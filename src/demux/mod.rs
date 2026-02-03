//! Packet demultiplexing
//!
//! Identifies packet types and extracts routing information.
//! Based on RFC 7983 for protocol multiplexing.

mod protocol;
mod rtp;
pub mod stun;

pub use protocol::{Demuxer, PacketType};
pub use rtp::RtpHeader;
pub use stun::{StunClass, StunInfo, StunMethod};
