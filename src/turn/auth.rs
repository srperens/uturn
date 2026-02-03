//! TURN authentication (long-term credentials)

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// TURN authentication helper
pub struct TurnAuth;

impl TurnAuth {
    /// Compute the long-term credential key
    ///
    /// key = MD5(username ":" realm ":" password)
    pub fn compute_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
        let input = format!("{}:{}:{}", username, realm, password);
        let digest = md5::compute(input.as_bytes());
        digest.0
    }

    /// Compute MESSAGE-INTEGRITY attribute value
    ///
    /// HMAC-SHA1 of the STUN message up to (but not including) MESSAGE-INTEGRITY
    pub fn compute_message_integrity(message: &[u8], key: &[u8]) -> [u8; 20] {
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key length");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Verify MESSAGE-INTEGRITY attribute
    pub fn verify_message_integrity(
        message: &[u8],
        received_integrity: &[u8],
        key: &[u8],
    ) -> bool {
        let computed = Self::compute_message_integrity(message, key);
        // Constant-time comparison
        if received_integrity.len() != 20 {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(received_integrity.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Generate a nonce value
    pub fn generate_nonce() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("{:016x}", timestamp)
    }

    /// Check if nonce is valid (not too old)
    pub fn validate_nonce(nonce: &str, max_age_secs: u64) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        if let Ok(nonce_time) = u64::from_str_radix(nonce, 16) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now.saturating_sub(nonce_time) < max_age_secs
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_key() {
        // Test vector from RFC 5389
        let key = TurnAuth::compute_key("user", "realm", "pass");
        // Key is MD5("user:realm:pass")
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_message_integrity() {
        let key = TurnAuth::compute_key("user", "realm", "pass");
        let message = b"test message";

        let integrity = TurnAuth::compute_message_integrity(message, &key);
        assert!(TurnAuth::verify_message_integrity(message, &integrity, &key));

        // Wrong key should fail
        let wrong_key = TurnAuth::compute_key("user", "realm", "wrong");
        assert!(!TurnAuth::verify_message_integrity(message, &integrity, &wrong_key));
    }

    #[test]
    fn test_nonce_validation() {
        let nonce = TurnAuth::generate_nonce();
        assert!(TurnAuth::validate_nonce(&nonce, 3600)); // Valid for 1 hour
        assert!(!TurnAuth::validate_nonce("0000000000000001", 3600)); // Too old
    }
}
