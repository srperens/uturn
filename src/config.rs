//! Server configuration

use std::net::IpAddr;

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// UDP port to listen on
    pub port: u16,

    /// External/public IP address
    ///
    /// This is the IP address that will be returned in TURN allocation responses
    /// as the relay address. Must be reachable by peers.
    pub external_ip: IpAddr,

    /// TURN realm for authentication
    pub realm: String,

    /// Static credentials (username, password)
    pub credentials: Vec<(String, String)>,
}

impl Config {
    /// Create a new config with minimal settings
    pub fn new(external_ip: IpAddr) -> Self {
        Self {
            port: 3478,
            external_ip,
            realm: "uturn".to_string(),
            credentials: Vec::new(),
        }
    }

    /// Set the listen port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the realm
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Add a credential
    pub fn with_credential(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials.push((username.into(), password.into()));
        self
    }

    /// Get password for username (if exists)
    pub fn get_password(&self, username: &str) -> Option<&str> {
        self.credentials
            .iter()
            .find(|(u, _)| u == username)
            .map(|(_, p)| p.as_str())
    }
}
