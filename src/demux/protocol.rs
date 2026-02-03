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
    fn parse_rtp_rtcp(data: &[u8]) -> PacketType {
        if data.len() < 12 {
            return PacketType::Unknown;
        }

        // Distinguish RTP from RTCP by payload type in second byte:
        // - RTP: PT is 7 bits (0-127), with marker bit in MSB
        // - RTCP: PT is full 8 bits: 200-204 (SR, RR, SDES, BYE, APP)
        //
        // RTCP PT values: SR=200 (0xC8), RR=201, SDES=202, BYE=203, APP=204
        // We check the raw byte without masking for RTCP detection.
        let pt = data[1];

        if (200..=204).contains(&pt) {
            PacketType::Rtcp(data.to_vec())
        } else {
            // Parse RTP header to get SSRC
            match RtpHeader::parse(data) {
                Some(header) => PacketType::Rtp {
                    ssrc: header.ssrc,
                    data: data.to_vec(),
                },
                None => PacketType::Unknown,
            }
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
        // RTCP Sender Report (PT=200, 0xC8)
        let rtcp_sr = [
            0x80, 0xC8, // V=2, PT=200 (SR)
            0x00, 0x06, // Length
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00, // NTP timestamp (high)
        ];
        assert!(matches!(Demuxer::classify(&rtcp_sr), PacketType::Rtcp(_)));

        // RTCP Receiver Report (PT=201, 0xC9)
        let rtcp_rr = [
            0x80, 0xC9, // V=2, PT=201 (RR)
            0x00, 0x01, // Length
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(Demuxer::classify(&rtcp_rr), PacketType::Rtcp(_)));

        // RTCP BYE (PT=203, 0xCB)
        let rtcp_bye = [
            0x80, 0xCB, // V=2, PT=203 (BYE)
            0x00, 0x01, // Length
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(Demuxer::classify(&rtcp_bye), PacketType::Rtcp(_)));
    }
}
