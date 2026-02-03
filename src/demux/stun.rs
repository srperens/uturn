//! STUN message parsing for demultiplexing
//!
//! Extracts ICE username fragment (ufrag) for session identification.

/// STUN magic cookie
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message type classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

/// STUN message type methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    Binding,
    Allocate,
    Refresh,
    Send,
    Data,
    CreatePermission,
    ChannelBind,
    Unknown(u16),
}

/// Parsed STUN information for demultiplexing
#[derive(Debug, Clone)]
pub struct StunInfo {
    /// Message class
    pub class: StunClass,

    /// Message method
    pub method: StunMethod,

    /// Transaction ID (96 bits)
    pub transaction_id: [u8; 12],

    /// USERNAME attribute (if present)
    /// Format: "serverUfrag:clientUfrag" for ICE
    pub username: Option<String>,

    /// Raw message bytes
    pub raw: Vec<u8>,
}

impl StunInfo {
    /// Parse STUN message header and USERNAME attribute
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        // Check magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != STUN_MAGIC_COOKIE {
            return None;
        }

        // Parse message type (first 2 bytes)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);

        // Extract class (bits 4, 8)
        let class_bits = ((msg_type >> 4) & 0x01) | ((msg_type >> 7) & 0x02);
        let class = match class_bits {
            0b00 => StunClass::Request,
            0b01 => StunClass::Indication,
            0b10 => StunClass::SuccessResponse,
            0b11 => StunClass::ErrorResponse,
            _ => return None,
        };

        // Extract method (bits 0-3, 5-7, 9-11)
        let method_bits = (msg_type & 0x000F)
            | ((msg_type >> 1) & 0x0070)
            | ((msg_type >> 2) & 0x0F80);
        let method = match method_bits {
            0x001 => StunMethod::Binding,
            0x003 => StunMethod::Allocate,
            0x004 => StunMethod::Refresh,
            0x006 => StunMethod::Send,
            0x007 => StunMethod::Data,
            0x008 => StunMethod::CreatePermission,
            0x009 => StunMethod::ChannelBind,
            other => StunMethod::Unknown(other),
        };

        // Message length
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 20 + msg_len {
            return None;
        }

        // Transaction ID (bytes 8-19)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse attributes to find USERNAME
        let username = Self::find_username(&data[20..20 + msg_len]);

        Some(Self {
            class,
            method,
            transaction_id,
            username,
            raw: data.to_vec(),
        })
    }

    /// Extract USERNAME attribute from STUN attributes
    fn find_username(attrs: &[u8]) -> Option<String> {
        let mut offset = 0;

        while offset + 4 <= attrs.len() {
            let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
            let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;

            // USERNAME attribute type = 0x0006
            if attr_type == 0x0006 {
                if offset + 4 + attr_len <= attrs.len() {
                    let value = &attrs[offset + 4..offset + 4 + attr_len];
                    return String::from_utf8(value.to_vec()).ok();
                }
            }

            // Move to next attribute (4-byte aligned)
            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }

        None
    }

    /// Extract ufrag pair from USERNAME attribute
    ///
    /// ICE USERNAME format: "serverUfrag:clientUfrag"
    pub fn parse_ice_username(&self) -> Option<(String, String)> {
        let username = self.username.as_ref()?;
        let parts: Vec<&str> = username.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Check if this is a TURN message (not just STUN binding)
    pub fn is_turn(&self) -> bool {
        matches!(
            self.method,
            StunMethod::Allocate
                | StunMethod::Refresh
                | StunMethod::Send
                | StunMethod::Data
                | StunMethod::CreatePermission
                | StunMethod::ChannelBind
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_binding_request() {
        let data = [
            0x00, 0x01, // Binding Request
            0x00, 0x00, // Length = 0
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x01, 0x02, 0x03, 0x04, // Transaction ID
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
        ];

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.class, StunClass::Request);
        assert_eq!(info.method, StunMethod::Binding);
    }

    #[test]
    fn test_parse_allocate_request() {
        let data = [
            0x00, 0x03, // Allocate Request
            0x00, 0x00, // Length = 0
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
        ];

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.method, StunMethod::Allocate);
        assert!(info.is_turn());
    }

    #[test]
    fn test_parse_with_username() {
        let username = b"serverufrag:clientufrag";
        let padded_len = (username.len() + 3) & !3;

        let mut data = vec![
            0x00, 0x01, // Binding Request
            0x00, (4 + padded_len) as u8, // Length
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
            // USERNAME attribute
            0x00, 0x06, // Type
            0x00, username.len() as u8, // Length
        ];
        data.extend_from_slice(username);
        // Add padding
        while data.len() < 20 + 4 + padded_len {
            data.push(0);
        }

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.username, Some("serverufrag:clientufrag".to_string()));

        let (server, client) = info.parse_ice_username().unwrap();
        assert_eq!(server, "serverufrag");
        assert_eq!(client, "clientufrag");
    }
}
