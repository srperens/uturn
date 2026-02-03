//! Protocol detection based on RFC 7983
//!
//! Multiplexing scheme for STUN, DTLS, RTP, RTCP, and TURN ChannelData.

use super::rtp::RtpHeader;
use super::stun::StunInfo;

/// Parsed packet type with extracted data
#[derive(Debug)]
pub enum PacketType {
    /// STUN message (binding request/response, TURN messages)
    Stun(StunInfo),

    /// DTLS record
    Dtls(Vec<u8>),

    /// TURN ChannelData
    TurnChannelData { channel: u16, data: Vec<u8> },

    /// RTP packet
    Rtp { ssrc: u32, data: Vec<u8> },

    /// RTCP packet
    Rtcp(Vec<u8>),

    /// Unknown packet type
    Unknown,
}

/// Packet demultiplexer
pub struct Demuxer;

impl Demuxer {
    /// Classify a packet based on its first byte (RFC 7983 + TURN extension)
    ///
    /// | Byte 1 Value | Protocol |
    /// |--------------|----------|
    /// | 0-3          | STUN     |
    /// | 20-63        | DTLS     |
    /// | 64-127       | TURN ChannelData (0x4000-0x7FFF) |
    /// | 128-191      | RTP/RTCP |
    ///
    /// Note: RFC 7983 only specifies 64-79 for ChannelData, but TURN (RFC 5766)
    /// allows channel numbers 0x4000-0x7FFF, which means first byte 64-127.
    pub fn classify(data: &[u8]) -> PacketType {
        if data.is_empty() {
            return PacketType::Unknown;
        }

        match data[0] {
            // STUN: first byte 0-3 (methods 0x000-0x3FF in first 2 bytes)
            0..=3 => Self::parse_stun(data),

            // DTLS: first byte 20-63 (content types)
            20..=63 => PacketType::Dtls(data.to_vec()),

            // TURN ChannelData: first byte 64-127 (channel numbers 0x4000-0x7FFF)
            64..=127 => Self::parse_channel_data(data),

            // RTP/RTCP: first byte 128-191 (version 2, various PT values)
            128..=191 => Self::parse_rtp_rtcp(data),

            _ => PacketType::Unknown,
        }
    }

    /// Parse STUN message
    fn parse_stun(data: &[u8]) -> PacketType {
        match StunInfo::parse(data) {
            Some(info) => PacketType::Stun(info),
            None => PacketType::Unknown,
        }
    }

    /// Parse TURN ChannelData
    fn parse_channel_data(data: &[u8]) -> PacketType {
        if data.len() < 4 {
            return PacketType::Unknown;
        }

        // ChannelData format:
        // 0-1: Channel Number (0x4000-0x7FFF)
        // 2-3: Length
        // 4+:  Application Data
        let channel = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return PacketType::Unknown;
        }

        PacketType::TurnChannelData {
            channel,
            data: data[4..4 + length].to_vec(),
        }
    }

    /// Parse RTP or RTCP packet
    ///
    /// Distinguishing RTP from RTCP is tricky because:
    /// - RTP second byte: [Marker (1 bit)][Payload Type (7 bits)]
    /// - RTCP second byte: [Packet Type (8 bits)] where PT is 200-204
    ///
    /// Problem: If RTP marker=1 and PT=72-76, raw byte becomes 200-204!
    /// (e.g., 0x80 | 72 = 200, same as RTCP SR)
    ///
    /// Solution per RFC 5761: Validate RTCP packet structure before classifying.
    fn parse_rtp_rtcp(data: &[u8]) -> PacketType {
        // Minimum header size: RTP needs 12 bytes, RTCP needs 8 bytes
        if data.len() < 8 {
            return PacketType::Unknown;
        }

        let raw_pt = data[1];

        // Check if this could be RTCP (raw byte 200-204)
        if (200..=204).contains(&raw_pt) {
            // Validate RTCP packet structure to avoid false positives
            if Self::is_valid_rtcp(data) {
                return PacketType::Rtcp(data.to_vec());
            }
            // Not valid RTCP, fall through to RTP parsing
        }

        // RTP requires at least 12 bytes for the fixed header
        if data.len() < 12 {
            return PacketType::Unknown;
        }

        // Parse as RTP
        match RtpHeader::parse(data) {
            Some(header) => PacketType::Rtp {
                ssrc: header.ssrc,
                data: data.to_vec(),
            },
            None => PacketType::Unknown,
        }
    }

    /// Validate RTCP packet structure
    ///
    /// RTCP header format:
    /// - Byte 0: [V (2 bits)][P (1 bit)][RC/SC (5 bits)]
    /// - Byte 1: [Packet Type (8 bits)] - 200-204
    /// - Bytes 2-3: Length (in 32-bit words minus one)
    ///
    /// We check:
    /// 1. Version = 2
    /// 2. Length field is consistent with packet size
    /// 3. Minimum size requirements for SR/RR
    fn is_valid_rtcp(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Check version = 2 (bits 6-7 of first byte)
        let version = (data[0] >> 6) & 0x03;
        if version != 2 {
            return false;
        }

        // Get length field (in 32-bit words minus 1)
        let length_field = u16::from_be_bytes([data[2], data[3]]) as usize;
        let packet_bytes = (length_field + 1) * 4;

        // RTCP packets can be compound (multiple packets concatenated)
        // The first packet's length should fit within the data
        if packet_bytes > data.len() {
            return false;
        }

        // Additional sanity check: RTCP SR/RR have minimum sizes
        let pt = data[1];
        let rc = data[0] & 0x1F; // Reception report count

        match pt {
            200 => {
                // SR: 28 bytes minimum (header with sender info) + 24 bytes per report block
                // Length field for SR with 0 report blocks = 6 (28 bytes = 7 words, minus 1 = 6)
                let min_words = 7 + (rc as usize * 6); // 7 words base + 6 words per report
                (length_field + 1) >= min_words
            }
            201 => {
                // RR: 8 bytes minimum (header) + 24 bytes per report block
                // Length field for RR with 0 report blocks = 1 (8 bytes = 2 words, minus 1 = 1)
                let min_words = 2 + (rc as usize * 6); // 2 words base + 6 words per report
                (length_field + 1) >= min_words
            }
            202..=204 => {
                // SDES, BYE, APP: just check we have a valid structure
                // packet_bytes >= 4 is already ensured by data.len() >= 8 check above
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_stun() {
        // STUN Binding Request magic cookie
        let stun_packet = [
            0x00, 0x01, // Binding Request
            0x00, 0x00, // Length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x00, 0x00, 0x00, 0x00, // Transaction ID (12 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            Demuxer::classify(&stun_packet),
            PacketType::Stun(_)
        ));
    }

    #[test]
    fn test_classify_dtls() {
        // DTLS record (content type 22 = handshake)
        let dtls_packet = [22, 0xfe, 0xff, 0x00, 0x00];
        assert!(matches!(
            Demuxer::classify(&dtls_packet),
            PacketType::Dtls(_)
        ));
    }

    #[test]
    fn test_classify_channel_data() {
        // TURN ChannelData
        let channel_data = [
            0x40, 0x00, // Channel 0x4000
            0x00, 0x04, // Length 4
            0xde, 0xad, 0xbe, 0xef, // Data
        ];
        assert!(matches!(
            Demuxer::classify(&channel_data),
            PacketType::TurnChannelData {
                channel: 0x4000,
                ..
            }
        ));
    }

    #[test]
    fn test_classify_rtp() {
        // RTP packet
        let rtp_packet = [
            0x80, 0x60, // V=2, PT=96
            0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x12, 0x34, 0x56, 0x78, // SSRC
        ];
        match Demuxer::classify(&rtp_packet) {
            PacketType::Rtp { ssrc, .. } => assert_eq!(ssrc, 0x12345678),
            _ => panic!("Expected RTP"),
        }
    }

    #[test]
    fn test_classify_rtcp() {
        // RTCP Sender Report (PT=200, 0xC8) - full 28 bytes
        let rtcp_sr = [
            0x80, 0xC8, // V=2, P=0, RC=0, PT=200 (SR)
            0x00, 0x06, // Length = 6 (7 words = 28 bytes)
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00, // NTP timestamp (high)
            0x00, 0x00, 0x00, 0x00, // NTP timestamp (low)
            0x00, 0x00, 0x00, 0x00, // RTP timestamp
            0x00, 0x00, 0x00, 0x00, // Packet count
            0x00, 0x00, 0x00, 0x00, // Octet count
        ];
        assert!(matches!(Demuxer::classify(&rtcp_sr), PacketType::Rtcp(_)));

        // RTCP Receiver Report (PT=201, 0xC9) - 8 bytes minimum
        let rtcp_rr = [
            0x80, 0xC9, // V=2, P=0, RC=0, PT=201 (RR)
            0x00, 0x01, // Length = 1 (2 words = 8 bytes)
            0x12, 0x34, 0x56, 0x78, // SSRC
        ];
        assert!(matches!(Demuxer::classify(&rtcp_rr), PacketType::Rtcp(_)));

        // RTCP BYE (PT=203, 0xCB)
        let rtcp_bye = [
            0x81, 0xCB, // V=2, P=0, SC=1, PT=203 (BYE)
            0x00, 0x01, // Length = 1 (2 words = 8 bytes)
            0x12, 0x34, 0x56, 0x78, // SSRC
        ];
        assert!(matches!(Demuxer::classify(&rtcp_bye), PacketType::Rtcp(_)));
    }

    #[test]
    fn test_rtp_with_marker_bit_not_misclassified_as_rtcp() {
        // RTP packet with marker bit set and PT=72
        // Raw byte 1 = 0x80 | 72 = 0xC8 = 200 (same as RTCP SR!)
        // This should be classified as RTP, not RTCP
        let rtp_marker_pt72 = [
            0x80, 0xC8, // V=2, M=1, PT=72 (raw byte = 200)
            0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x12, 0x34, 0x56, 0x78, // SSRC
            0xde, 0xad, 0xbe, 0xef, // Payload (not valid RTCP structure)
        ];

        // This should be RTP because the packet doesn't have valid RTCP structure
        // (length field says 1 word = 8 bytes, but RTCP SR needs at least 28 bytes)
        match Demuxer::classify(&rtp_marker_pt72) {
            PacketType::Rtp { ssrc, .. } => assert_eq!(ssrc, 0x12345678),
            other => panic!("Expected RTP, got {:?}", other),
        }
    }

    #[test]
    fn test_valid_rtcp_sr_not_misclassified() {
        // Valid RTCP Sender Report
        // SR = 28 bytes minimum (7 words), with RC=0
        let rtcp_sr = [
            0x80, 0xC8, // V=2, P=0, RC=0, PT=200 (SR)
            0x00, 0x06, // Length = 6 words (28 bytes total)
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00, // NTP timestamp (high)
            0x00, 0x00, 0x00, 0x00, // NTP timestamp (low)
            0x00, 0x00, 0x00, 0x00, // RTP timestamp
            0x00, 0x00, 0x00, 0x00, // Packet count
            0x00, 0x00, 0x00, 0x00, // Octet count
        ];
        assert!(matches!(Demuxer::classify(&rtcp_sr), PacketType::Rtcp(_)));
    }
}
