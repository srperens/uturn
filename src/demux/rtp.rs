//! RTP header parsing
//!
//! Extracts SSRC for demultiplexing. We only need the fixed header,
//! not the full RTP parsing.

/// Minimal RTP header for demultiplexing
#[derive(Debug, Clone)]
pub struct RtpHeader {
    /// RTP version (should be 2)
    pub version: u8,

    /// Padding flag
    pub padding: bool,

    /// Extension flag
    pub extension: bool,

    /// CSRC count
    pub csrc_count: u8,

    /// Marker bit
    pub marker: bool,

    /// Payload type
    pub payload_type: u8,

    /// Sequence number
    pub sequence_number: u16,

    /// Timestamp
    pub timestamp: u32,

    /// Synchronization source identifier
    pub ssrc: u32,
}

impl RtpHeader {
    /// Parse RTP header from bytes
    ///
    /// Returns None if the packet is too small or invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let first_byte = data[0];
        let second_byte = data[1];

        let version = (first_byte >> 6) & 0x03;
        if version != 2 {
            return None;
        }

        let padding = (first_byte & 0x20) != 0;
        let extension = (first_byte & 0x10) != 0;
        let csrc_count = first_byte & 0x0F;

        let marker = (second_byte & 0x80) != 0;
        let payload_type = second_byte & 0x7F;

        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // Validate minimum size including CSRC list
        let min_size = 12 + (csrc_count as usize * 4);
        if data.len() < min_size {
            return None;
        }

        Some(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
        })
    }

    /// Get the header size in bytes (including CSRC list)
    pub fn header_size(&self) -> usize {
        12 + (self.csrc_count as usize * 4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_rtp() {
        let data = [
            0x80, 0x60, // V=2, P=0, X=0, CC=0, M=0, PT=96
            0x00, 0x01, // Seq=1
            0x00, 0x00, 0x03, 0xe8, // Timestamp=1000
            0xab, 0xcd, 0xef, 0x12, // SSRC
        ];

        let header = RtpHeader::parse(&data).unwrap();
        assert_eq!(header.version, 2);
        assert!(!header.padding);
        assert!(!header.extension);
        assert_eq!(header.csrc_count, 0);
        assert!(!header.marker);
        assert_eq!(header.payload_type, 96);
        assert_eq!(header.sequence_number, 1);
        assert_eq!(header.timestamp, 1000);
        assert_eq!(header.ssrc, 0xabcdef12);
    }

    #[test]
    fn test_parse_rtp_with_marker() {
        let data = [
            0x80, 0xe0, // V=2, M=1, PT=96
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        let header = RtpHeader::parse(&data).unwrap();
        assert!(header.marker);
    }

    #[test]
    fn test_parse_too_short() {
        let data = [0x80, 0x60, 0x00];
        assert!(RtpHeader::parse(&data).is_none());
    }

    #[test]
    fn test_parse_wrong_version() {
        let data = [
            0x40, 0x60, // V=1 (invalid)
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert!(RtpHeader::parse(&data).is_none());
    }
}
