//! TURN message handler

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, trace, warn};

use crate::config::Config;
use crate::demux::StunInfo;
use crate::lookup::{AllocationTable, RateLimitError, RateLimiter};

use super::auth::TurnAuth;
use super::message::TurnErrorCode;

/// TURN protocol handler
pub struct TurnHandler {
    config: Arc<Config>,
    allocations: Arc<AllocationTable>,
    rate_limiter: Arc<RateLimiter>,
}

/// Result of authentication validation
enum AuthResult {
    /// Authentication successful, here's the key for response
    Success([u8; 16]),
    /// No authentication required (anonymous mode)
    NotRequired,
    /// Authentication failed, send this error response
    Failed(Vec<u8>),
}

impl TurnHandler {
    /// Create a new handler
    pub fn new(
        config: Arc<Config>,
        allocations: Arc<AllocationTable>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            config,
            allocations,
            rate_limiter,
        }
    }

    /// Validate authentication for requests that require it (Refresh, CreatePermission, ChannelBind)
    ///
    /// Per RFC 5766 Section 10.1: All requests after the initial Allocate must be
    /// authenticated using the same credentials as the Allocate request.
    fn validate_request_auth(&self, msg: &StunInfo, expected_username: &str) -> AuthResult {
        // If no credentials configured, authentication is not required
        if self.config.credentials.is_empty() {
            return AuthResult::NotRequired;
        }

        // Check MESSAGE-INTEGRITY is present
        if msg.message_integrity.is_none() {
            return AuthResult::Failed(self.build_unauthorized_response(msg));
        }

        // Check USERNAME matches the allocation's username
        let username = match &msg.username {
            Some(u) => u,
            None => {
                return AuthResult::Failed(
                    self.build_error_response(msg, TurnErrorCode::BadRequest),
                );
            }
        };

        if username != expected_username {
            warn!(
                "Username mismatch: expected '{}', got '{}'",
                expected_username, username
            );
            return AuthResult::Failed(self.build_unauthorized_response(msg));
        }

        // Get password for this user
        let password = match self.config.get_password(username) {
            Some(p) => p,
            None => {
                return AuthResult::Failed(self.build_unauthorized_response(msg));
            }
        };

        // Validate nonce freshness
        if let Some(ref nonce) = msg.nonce {
            if !TurnAuth::validate_nonce(
                nonce,
                self.config.nonce_lifetime_secs,
                &self.config.nonce_secret,
            ) {
                // 438 Stale Nonce must include REALM and fresh NONCE per RFC 5389
                return AuthResult::Failed(self.build_stale_nonce_response(msg));
            }
        } else {
            return AuthResult::Failed(self.build_error_response(msg, TurnErrorCode::BadRequest));
        }

        // Validate REALM - required for long-term credentials per RFC 5389
        let client_realm = msg.realm.as_deref();
        match client_realm {
            Some(realm) if realm != self.config.realm => {
                warn!(
                    "Realm mismatch: client sent '{}', expected '{}'",
                    realm, self.config.realm
                );
                return AuthResult::Failed(self.build_unauthorized_response(msg));
            }
            None => {
                // REALM is required for long-term credentials per RFC 5389
                warn!("Missing REALM attribute in authenticated request");
                return AuthResult::Failed(self.build_unauthorized_response(msg));
            }
            _ => {} // Realm matches
        }

        // Always use server's realm for key computation
        let key = TurnAuth::compute_key(username, &self.config.realm, password);

        if let (Some(integrity), Some(offset)) =
            (&msg.message_integrity, msg.message_integrity_offset)
        {
            // Build message up to MESSAGE-INTEGRITY for validation
            let mut msg_for_hmac = msg.raw[..offset].to_vec();
            let new_len = (offset - 20 + 24) as u16;
            msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());

            if !TurnAuth::verify_message_integrity(&msg_for_hmac, integrity, &key) {
                return AuthResult::Failed(self.build_unauthorized_response(msg));
            }

            AuthResult::Success(key)
        } else {
            AuthResult::Failed(self.build_error_response(msg, TurnErrorCode::BadRequest))
        }
    }

    /// Handle incoming STUN/TURN message
    pub async fn handle_stun(
        &self,
        msg: StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        use crate::demux::stun::{StunClass, StunMethod};

        match (&msg.class, &msg.method) {
            // STUN Binding Request (ICE connectivity check)
            (StunClass::Request, StunMethod::Binding) => {
                self.handle_binding_request(&msg, src_addr, socket).await
            }

            // TURN Allocate
            (StunClass::Request, StunMethod::Allocate) => {
                self.handle_allocate(&msg, src_addr, socket).await
            }

            // TURN Refresh
            (StunClass::Request, StunMethod::Refresh) => {
                self.handle_refresh(&msg, src_addr, socket).await
            }

            // TURN CreatePermission
            (StunClass::Request, StunMethod::CreatePermission) => {
                self.handle_create_permission(&msg, src_addr, socket).await
            }

            // TURN ChannelBind
            (StunClass::Request, StunMethod::ChannelBind) => {
                self.handle_channel_bind(&msg, src_addr, socket).await
            }

            // TURN Send (client -> peer via indication)
            (StunClass::Indication, StunMethod::Send) => {
                self.handle_send(&msg, src_addr, socket).await
            }

            // Handle STUN responses from clients - relay them to peers
            (StunClass::SuccessResponse, _) | (StunClass::ErrorResponse, _) => {
                // If this is from a client with an allocation, relay to peers
                if self.allocations.lookup_by_source(src_addr).is_some() {
                    self.handle_client_response(&msg, src_addr, socket).await
                } else {
                    debug!(
                        "Unhandled STUN response: {:?} {:?} from {}",
                        msg.class, msg.method, src_addr
                    );
                    Ok(())
                }
            }

            _ => {
                debug!(
                    "Unhandled STUN message: {:?} {:?} from {}",
                    msg.class, msg.method, src_addr
                );
                Ok(())
            }
        }
    }

    /// Handle STUN Binding Request
    async fn handle_binding_request(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Binding request from {}", src_addr);

        // Build binding response with XOR-MAPPED-ADDRESS
        let response = self.build_binding_response(msg, src_addr);
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle STUN response from a client - relay to peers
    async fn handle_client_response(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Client response from {} - relaying to peers", src_addr);

        // Find allocations that have permission for this client's IP
        let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());

        for alloc_id in candidates {
            if let Some(target_alloc) = self.allocations.get(alloc_id) {
                // Skip if target is same as source
                if target_alloc.client_addr == src_addr {
                    continue;
                }

                debug!(
                    "Relaying response from {} to {} via Data Indication",
                    src_addr, target_alloc.client_addr
                );

                // Build and send Data Indication with the raw STUN response
                let indication = self.build_data_indication(src_addr, &msg.raw);
                socket
                    .send_to(&indication, target_alloc.client_addr)
                    .await?;
            }
        }

        Ok(())
    }

    /// Handle TURN Allocate Request
    async fn handle_allocate(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        info!("Allocate request from {}", src_addr);

        // 1. Check if already allocated - treat as retransmission and return success
        if let Some(alloc) = self.allocations.get_by_client(src_addr) {
            debug!(
                "Allocation already exists for {} - returning success for retransmission",
                src_addr
            );
            let lifetime = alloc.remaining_lifetime();
            let username = alloc.username.clone();
            drop(alloc);

            // For retransmission, we need to include MESSAGE-INTEGRITY if auth is enabled
            let key = if !self.config.credentials.is_empty() {
                self.config
                    .get_password(&username)
                    .map(|password| TurnAuth::compute_key(&username, &self.config.realm, password))
            } else {
                None
            };
            let response = self.build_allocate_response(msg, src_addr, lifetime, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // 2. Validate REQUESTED-TRANSPORT (RFC 5766 requires UDP = 17)
        // This is checked before auth/rate-limit as it's a protocol error
        match msg.requested_transport {
            Some(17) => {
                // UDP is supported
            }
            Some(other) => {
                warn!("Unsupported transport protocol {} from {}", other, src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::UnsupportedTransport);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            None => {
                // Per RFC 5766, REQUESTED-TRANSPORT is required. However, some clients
                // may omit it for UDP-only servers. We'll be lenient and assume UDP.
                debug!("Allocate request missing REQUESTED-TRANSPORT, assuming UDP");
            }
        }

        // 3. Authentication check BEFORE rate limiting
        // Auth failures should return 401, not 508 (rate limit errors)
        // Only valid auth attempts should count against rate limits
        if !self.config.credentials.is_empty() {
            // Check if MESSAGE-INTEGRITY is present
            if msg.message_integrity.is_none() {
                // First request without credentials - send 401 with REALM and NONCE
                debug!("Allocate request missing MESSAGE-INTEGRITY, sending 401");
                let response = self.build_unauthorized_response(msg);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            // Validate credentials
            let username = match &msg.username {
                Some(u) => u,
                None => {
                    warn!("Allocate request has MESSAGE-INTEGRITY but no USERNAME");
                    let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            let password = match self.config.get_password(username) {
                Some(p) => p,
                None => {
                    warn!("Unknown username in Allocate request: {}", username);
                    let response = self.build_unauthorized_response(msg);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            // Validate nonce freshness
            if let Some(ref nonce) = msg.nonce {
                if !TurnAuth::validate_nonce(
                    nonce,
                    self.config.nonce_lifetime_secs,
                    &self.config.nonce_secret,
                ) {
                    warn!("Stale nonce from {}", src_addr);
                    // 438 Stale Nonce must include REALM and fresh NONCE per RFC 5389
                    let response = self.build_stale_nonce_response(msg);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            } else {
                warn!("Missing nonce from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            // Validate REALM - required for long-term credentials per RFC 5389
            let client_realm = msg.realm.as_deref();
            match client_realm {
                Some(realm) if realm != self.config.realm => {
                    warn!(
                        "Realm mismatch from {}: client sent '{}', expected '{}'",
                        src_addr, realm, self.config.realm
                    );
                    let response = self.build_unauthorized_response(msg);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
                None => {
                    // REALM is required for long-term credentials per RFC 5389
                    warn!(
                        "Missing REALM attribute in Allocate request from {}",
                        src_addr
                    );
                    let response = self.build_unauthorized_response(msg);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
                _ => {} // Realm matches
            }

            // Always use server's realm for key computation
            let key = TurnAuth::compute_key(username, &self.config.realm, password);

            if let (Some(integrity), Some(offset)) =
                (&msg.message_integrity, msg.message_integrity_offset)
            {
                // Build message up to MESSAGE-INTEGRITY for validation
                // Need to adjust the length in header to end at MESSAGE-INTEGRITY
                let mut msg_for_hmac = msg.raw[..offset].to_vec();
                // Adjust length: offset - 20 (header) + 24 (MESSAGE-INTEGRITY attr size)
                let new_len = (offset - 20 + 24) as u16;
                msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());

                if !TurnAuth::verify_message_integrity(&msg_for_hmac, integrity, &key) {
                    warn!("Invalid MESSAGE-INTEGRITY from {}", src_addr);
                    let response = self.build_unauthorized_response(msg);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }

                debug!("MESSAGE-INTEGRITY validated for user {}", username);
            } else {
                warn!("MESSAGE-INTEGRITY parsing error");
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            // 4. Authentication passed - NOW check rate limits
            if let Err(e) = self.rate_limiter.check_allocation_request(src_addr.ip()) {
                warn!("Allocate request rejected for {}: {}", src_addr, e);
                let error_code = match e {
                    RateLimitError::TooManyRequests => TurnErrorCode::InsufficientCapacity,
                    RateLimitError::QuotaExceeded => TurnErrorCode::AllocationQuotaReached,
                };
                let response = self.build_error_response(msg, error_code);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            // 5. Valid credentials and rate limit passed - create allocation atomically
            let lifetime = 60;
            let (alloc_id, created) =
                self.allocations
                    .create_or_get(src_addr, username.to_string(), lifetime);

            if !created {
                // Concurrent request won the race - treat as retransmission
                // Cancel rate limiter reservation since we didn't create a new allocation
                debug!(
                    "Concurrent allocation created for {} - treating as retransmission",
                    src_addr
                );
                self.rate_limiter.cancel_reservation(src_addr.ip());
            } else {
                info!(
                    "Created allocation {} for {} (user: {})",
                    alloc_id, src_addr, username
                );
            }

            // Get actual lifetime from allocation (may be different if existing)
            let actual_lifetime = self
                .allocations
                .get(alloc_id)
                .map(|a| a.remaining_lifetime())
                .unwrap_or(lifetime);

            let response = self.build_allocate_response(msg, src_addr, actual_lifetime, Some(&key));
            debug!(
                "Sending Allocate response ({} bytes) to {}: {:02x?}",
                response.len(),
                src_addr,
                &response[..std::cmp::min(response.len(), 64)]
            );
            socket.send_to(&response, src_addr).await?;
        } else {
            // No authentication configured - anonymous access
            // Check rate limits for anonymous requests
            if let Err(e) = self.rate_limiter.check_allocation_request(src_addr.ip()) {
                warn!("Allocate request rejected for {}: {}", src_addr, e);
                let error_code = match e {
                    RateLimitError::TooManyRequests => TurnErrorCode::InsufficientCapacity,
                    RateLimitError::QuotaExceeded => TurnErrorCode::AllocationQuotaReached,
                };
                let response = self.build_error_response(msg, error_code);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            let username = msg.username.as_deref().unwrap_or("anonymous");

            // Create allocation atomically
            let lifetime = 60;
            let (alloc_id, created) =
                self.allocations
                    .create_or_get(src_addr, username.to_string(), lifetime);

            if !created {
                // Concurrent request won the race - treat as retransmission
                debug!(
                    "Concurrent allocation created for {} - treating as retransmission",
                    src_addr
                );
                self.rate_limiter.cancel_reservation(src_addr.ip());
            } else {
                info!(
                    "Created allocation {} for {} (user: {})",
                    alloc_id, src_addr, username
                );
            }

            // Get actual lifetime from allocation (may be different if existing)
            let actual_lifetime = self
                .allocations
                .get(alloc_id)
                .map(|a| a.remaining_lifetime())
                .unwrap_or(lifetime);

            let response = self.build_allocate_response(msg, src_addr, actual_lifetime, None);
            debug!(
                "Sending Allocate response ({} bytes) to {}: {:02x?}",
                response.len(),
                src_addr,
                &response[..std::cmp::min(response.len(), 64)]
            );
            socket.send_to(&response, src_addr).await?;
        }

        Ok(())
    }

    /// Handle TURN Refresh Request
    async fn handle_refresh(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Refresh request from {}", src_addr);

        let alloc = match self.allocations.get_by_client(src_addr) {
            Some(a) => a,
            None => {
                let response = self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Validate authentication (RFC 5766 Section 10.1)
        let key = match self.validate_request_auth(msg, &alloc.username) {
            AuthResult::Success(k) => Some(k),
            AuthResult::NotRequired => None,
            AuthResult::Failed(response) => {
                warn!("Refresh auth failed from {}", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse requested lifetime (0 means delete allocation)
        let requested_lifetime = msg.lifetime.unwrap_or(60);

        if requested_lifetime == 0 {
            // Client wants to delete the allocation
            let alloc_id = alloc.id;
            drop(alloc); // Release the ref before removing
            self.allocations.remove(alloc_id);
            self.rate_limiter.record_deallocation(src_addr.ip());
            info!(
                "Deleted allocation {} for {} (lifetime=0)",
                alloc_id, src_addr
            );

            let response = self.build_refresh_response(msg, 0, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Cap lifetime at 60 seconds max, minimum 10 seconds
        let lifetime = requested_lifetime.clamp(10, 60);
        alloc.refresh(lifetime);
        alloc.touch_received();

        debug!(
            "Refreshed allocation for {} (lifetime={}s)",
            src_addr, lifetime
        );

        let response = self.build_refresh_response(msg, lifetime, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN CreatePermission Request
    async fn handle_create_permission(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("CreatePermission request from {}", src_addr);

        // Parse XOR-PEER-ADDRESS attributes first (can have multiple)
        if msg.xor_peer_addresses.is_empty() {
            warn!(
                "CreatePermission missing XOR-PEER-ADDRESS from {}",
                src_addr
            );
            let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        let (alloc_id, key) = {
            let alloc = match self.allocations.get_by_client(src_addr) {
                Some(a) => a,
                None => {
                    let response =
                        self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            // Validate authentication (RFC 5766 Section 10.1)
            let key = match self.validate_request_auth(msg, &alloc.username) {
                AuthResult::Success(k) => Some(k),
                AuthResult::NotRequired => None,
                AuthResult::Failed(response) => {
                    warn!("CreatePermission auth failed from {}", src_addr);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            alloc.touch_received();
            (alloc.id, key)
        };

        // Add permissions for each peer IP (must use table method to update index)
        for peer_addr in &msg.xor_peer_addresses {
            let peer_ip = peer_addr.ip();
            self.allocations.add_permission(alloc_id, peer_ip);
            debug!(
                "Added permission for {} to allocation {}",
                peer_ip, alloc_id
            );
        }

        info!(
            "CreatePermission: added {} peer(s) for {} (alloc {})",
            msg.xor_peer_addresses.len(),
            src_addr,
            alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN ChannelBind Request
    async fn handle_channel_bind(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("ChannelBind request from {}", src_addr);

        // Parse CHANNEL-NUMBER
        let channel = match msg.channel_number {
            Some(ch) => ch,
            None => {
                warn!("ChannelBind missing CHANNEL-NUMBER from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse XOR-PEER-ADDRESS (ChannelBind uses only one peer address)
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("ChannelBind missing XOR-PEER-ADDRESS from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        let (alloc_id, key) = {
            let alloc = match self.allocations.get_by_client(src_addr) {
                Some(a) => a,
                None => {
                    let response =
                        self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            // Validate authentication (RFC 5766 Section 10.1)
            let key = match self.validate_request_auth(msg, &alloc.username) {
                AuthResult::Success(k) => Some(k),
                AuthResult::NotRequired => None,
                AuthResult::Failed(response) => {
                    warn!("ChannelBind auth failed from {}", src_addr);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            let alloc_id = alloc.id;

            // Bind channel (this can be done while holding the ref)
            alloc.bind_channel(channel, peer_addr);
            alloc.touch_received();

            (alloc_id, key)
        };

        // Add permission through the table method to update index
        self.allocations.add_permission(alloc_id, peer_addr.ip());

        info!(
            "ChannelBind: channel 0x{:04x} -> {} for {} (alloc {})",
            channel, peer_addr, src_addr, alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Send Indication
    async fn handle_send(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Send indication from {}", src_addr);

        // Get allocation for this client
        let alloc = match self.allocations.get_by_client(src_addr) {
            Some(a) => a,
            None => {
                trace!("Send indication from unknown client: {}", src_addr);
                return Ok(());
            }
        };

        // Get peer address
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("Send indication missing XOR-PEER-ADDRESS from {}", src_addr);
                return Ok(());
            }
        };

        // Prevent sending to ourselves (would create a loop)
        let our_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        if peer_addr == our_addr {
            // This is valid in single-port TURN - both clients may have the same relay address
            // In this case, we need to find OTHER allocations that have permission for our relay
            // and send the data to them
            debug!("Send to our own relay address - routing internally");

            // Check that the SENDER has permission for the relay IP (RFC 5766 requirement)
            if !alloc.is_permitted(self.config.external_ip) {
                warn!(
                    "Send indication to relay address from {} without permission",
                    src_addr
                );
                return Ok(());
            }

            let data = match &msg.data {
                Some(d) => d,
                None => return Ok(()),
            };

            // Find all allocations that have permission for our relay IP (excluding sender)
            let candidates = self.allocations.lookup_by_peer_ip(self.config.external_ip);
            let mut sent = false;

            for alloc_id in candidates {
                if let Some(target_alloc) = self.allocations.get(alloc_id) {
                    // Skip the sender's own allocation
                    if target_alloc.client_addr == src_addr {
                        continue;
                    }

                    debug!(
                        "Internal relay: {} bytes from {} to {}",
                        data.len(),
                        src_addr,
                        target_alloc.client_addr
                    );

                    // Build and send Data Indication to target client
                    // The peer address from target's perspective is the relay address
                    // (since they created permission for the relay, not the sender)
                    let indication = self.build_data_indication(our_addr, data);
                    socket
                        .send_to(&indication, target_alloc.client_addr)
                        .await?;
                    sent = true;
                }
            }

            if !sent {
                trace!(
                    "No target allocation found for internal routing from {}",
                    src_addr
                );
            }

            // Touch sender's allocation - they're actively sending data
            alloc.touch_received();
            return Ok(());
        }

        // Get data
        let data = match &msg.data {
            Some(d) => d,
            None => {
                trace!("Send indication missing DATA from {}", src_addr);
                return Ok(());
            }
        };

        // Check permission
        if !alloc.is_permitted(peer_addr.ip()) {
            warn!(
                "Send indication to unpermitted peer {} from {}",
                peer_addr, src_addr
            );
            return Ok(());
        }

        // Relay data to peer
        debug!(
            "Relaying {} bytes from {} to peer {}",
            data.len(),
            src_addr,
            peer_addr
        );
        socket.send_to(data, peer_addr).await?;
        alloc.touch_received();

        Ok(())
    }

    /// Build a STUN Binding Response
    fn build_binding_response(&self, request: &StunInfo, client_addr: SocketAddr) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        // Message type: Binding Success Response (0x0101)
        response.extend_from_slice(&[0x01, 0x01]);

        // Placeholder for length (will be filled later)
        response.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID
        response.extend_from_slice(&request.transaction_id);

        // XOR-MAPPED-ADDRESS attribute
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a TURN Allocate Success Response
    fn build_allocate_response(
        &self,
        request: &StunInfo,
        client_addr: SocketAddr,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(96);

        // Message type: Allocate Success Response (0x0103)
        response.extend_from_slice(&[0x01, 0x03]);
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        response.extend_from_slice(&request.transaction_id);

        // XOR-RELAYED-ADDRESS (our single port!)
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        self.append_xor_relayed_address(&mut response, relay_addr, &request.transaction_id);

        // XOR-MAPPED-ADDRESS
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a TURN Refresh Success Response
    fn build_refresh_response(
        &self,
        request: &StunInfo,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Message type: Refresh Success Response (0x0104)
        response.extend_from_slice(&[0x01, 0x04]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a generic success response
    fn build_success_response(&self, request: &StunInfo, key: Option<&[u8; 16]>) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Success response: set bit 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let success_type = msg_type | 0x0100;

        response.extend_from_slice(&success_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build an error response
    fn build_error_response(&self, request: &StunInfo, error: TurnErrorCode) -> Vec<u8> {
        let mut response = Vec::with_capacity(48);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009)
        let reason = error.reason();
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes()); // Length
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push((error as u16 / 100) as u8); // Class
        response.push((error as u16 % 100) as u8); // Number
        response.extend_from_slice(reason.as_bytes());

        // Padding (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Append XOR-MAPPED-ADDRESS attribute
    fn append_xor_mapped_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0020
        buf.extend_from_slice(&[0x00, 0x20]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length = 8
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4 family

                // XOR port with magic cookie upper 16 bits
                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie
                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                // XOR port with magic cookie upper 16 bits
                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie (4 bytes) + transaction ID (12 bytes)
                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }

    /// Append XOR-RELAYED-ADDRESS attribute
    fn append_xor_relayed_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0016
        buf.extend_from_slice(&[0x00, 0x16]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]);
                buf.push(0x00);
                buf.push(0x01);

                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }

    /// Append LIFETIME attribute
    fn append_lifetime(&self, buf: &mut Vec<u8>, lifetime: u32) {
        buf.extend_from_slice(&[0x00, 0x0d]); // Type
        buf.extend_from_slice(&[0x00, 0x04]); // Length
        buf.extend_from_slice(&lifetime.to_be_bytes());
    }

    /// Build a 401 Unauthorized response with REALM and NONCE
    fn build_unauthorized_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 401 Unauthorized
        let reason = "Unauthorized";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (401 / 100)
        response.push(1); // Number (401 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a 438 Stale Nonce response with REALM and fresh NONCE
    ///
    /// Per RFC 5389, 438 responses must include REALM and NONCE so clients
    /// can retry with the new nonce.
    fn build_stale_nonce_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 438 Stale Nonce
        let reason = "Stale Nonce";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (438 / 100)
        response.push(38); // Number (438 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute - required for client to retry
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute - fresh nonce for client to use
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Append REALM attribute (0x0014)
    fn append_realm(&self, buf: &mut Vec<u8>, realm: &str) {
        let realm_bytes = realm.as_bytes();
        let padded_len = (realm_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x14]); // Type
        buf.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(realm_bytes);

        // Padding
        for _ in realm_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append NONCE attribute (0x0015)
    fn append_nonce(&self, buf: &mut Vec<u8>, nonce: &str) {
        let nonce_bytes = nonce.as_bytes();
        let padded_len = (nonce_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x15]); // Type
        buf.extend_from_slice(&(nonce_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(nonce_bytes);

        // Padding
        for _ in nonce_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append MESSAGE-INTEGRITY attribute (0x0008)
    fn append_message_integrity(&self, buf: &mut Vec<u8>, key: &[u8; 16]) {
        // First, update the length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
        let new_len = (buf.len() - 20 + 24) as u16;
        buf[2..4].copy_from_slice(&new_len.to_be_bytes());

        // Compute HMAC-SHA1 over message up to this point
        let integrity = TurnAuth::compute_message_integrity(buf, key);

        // Append MESSAGE-INTEGRITY attribute
        buf.extend_from_slice(&[0x00, 0x08]); // Type
        buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
        buf.extend_from_slice(&integrity);
    }

    /// Build a TURN Data Indication
    fn build_data_indication(&self, peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(48 + data.len());

        // Data Indication: 0x0017
        packet.extend_from_slice(&[0x00, 0x17]);

        // Length placeholder
        packet.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        packet.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID (random for indication per RFC 5389)
        let txn_id: [u8; 12] = rand::random();
        packet.extend_from_slice(&txn_id);

        // XOR-PEER-ADDRESS attribute (0x0012)
        self.append_xor_peer_address(&mut packet, peer_addr, &txn_id);

        // DATA attribute (0x0013)
        packet.extend_from_slice(&[0x00, 0x13]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad DATA attribute
        while (packet.len() - 20) % 4 != 0 {
            packet.push(0);
        }

        // Update length
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        packet
    }

    /// Append XOR-PEER-ADDRESS attribute (0x0012)
    fn append_xor_peer_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        buf.extend_from_slice(&[0x00, 0x12]); // Type

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4

                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }
}
