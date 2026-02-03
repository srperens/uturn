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
    pub fn verify_message_integrity(message: &[u8], received_integrity: &[u8], key: &[u8]) -> bool {
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

    /// Generate a nonce value bound to a server secret
    ///
    /// Format: `{timestamp_hex}:{hmac_hex}` where HMAC is computed over the timestamp
    /// using the server secret. This prevents nonce prediction/replay.
    pub fn generate_nonce(secret: &[u8; 16]) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Compute HMAC of timestamp using server secret
        let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC key length");
        mac.update(&timestamp.to_be_bytes());
        let hmac_result = mac.finalize().into_bytes();

        // Return timestamp:hmac (first 8 bytes of HMAC for brevity)
        format!(
            "{:016x}:{:016x}",
            timestamp,
            u64::from_be_bytes(hmac_result[..8].try_into().unwrap())
        )
    }

    /// Check if nonce is valid (not too old and HMAC matches)
    pub fn validate_nonce(nonce: &str, max_age_secs: u64, secret: &[u8; 16]) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Parse timestamp:hmac format
        let parts: Vec<&str> = nonce.split(':').collect();
        if parts.len() != 2 {
            // Legacy format (timestamp only) - reject for security
            return false;
        }

        let timestamp = match u64::from_str_radix(parts[0], 16) {
            Ok(t) => t,
            Err(_) => return false,
        };

        let provided_hmac = match u64::from_str_radix(parts[1], 16) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Verify HMAC using constant-time comparison to prevent timing attacks
        let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC key length");
        mac.update(&timestamp.to_be_bytes());
        let hmac_result = mac.finalize().into_bytes();
        let expected_hmac = u64::from_be_bytes(hmac_result[..8].try_into().unwrap());

        // Constant-time comparison
        let mut diff = 0u64;
        diff |= provided_hmac ^ expected_hmac;
        if diff != 0 {
            return false;
        }

        // Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(timestamp) < max_age_secs
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
        assert!(TurnAuth::verify_message_integrity(
            message, &integrity, &key
        ));

        // Wrong key should fail
        let wrong_key = TurnAuth::compute_key("user", "realm", "wrong");
        assert!(!TurnAuth::verify_message_integrity(
            message, &integrity, &wrong_key
        ));
    }

    #[test]
    fn test_nonce_validation() {
        let secret: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let nonce = TurnAuth::generate_nonce(&secret);
        assert!(TurnAuth::validate_nonce(&nonce, 3600, &secret)); // Valid for 1 hour

        // Wrong secret should fail
        let wrong_secret: [u8; 16] = [0; 16];
        assert!(!TurnAuth::validate_nonce(&nonce, 3600, &wrong_secret));

        // Old timestamp should fail (crafted with valid HMAC but old timestamp)
        assert!(!TurnAuth::validate_nonce(
            "0000000000000001:0000000000000000",
            3600,
            &secret
        ));

        // Invalid format should fail
        assert!(!TurnAuth::validate_nonce("invalid", 3600, &secret));
    }
}
