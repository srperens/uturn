//! TURN message handler

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::demux::StunInfo;
use crate::lookup::AllocationTable;

use super::auth::TurnAuth;
use super::message::TurnErrorCode;

/// TURN protocol handler
pub struct TurnHandler {
    config: Arc<Config>,
    allocations: Arc<AllocationTable>,
}

impl TurnHandler {
    /// Create a new handler
    pub fn new(config: Arc<Config>, allocations: Arc<AllocationTable>) -> Self {
        Self {
            config,
            allocations,
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
                socket.send_to(&indication, target_alloc.client_addr).await?;
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

        // Check if already allocated - treat as retransmission and return success
        if let Some(alloc) = self.allocations.get_by_client(src_addr) {
            debug!("Allocation already exists for {} - returning success for retransmission", src_addr);
            let lifetime = alloc.remaining_lifetime();
            let username = alloc.username.clone();
            drop(alloc);

            // For retransmission, we need to include MESSAGE-INTEGRITY if auth is enabled
            let key = if !self.config.credentials.is_empty() {
                self.config.get_password(&username).map(|password| {
                    TurnAuth::compute_key(&username, &self.config.realm, password)
                })
            } else {
                None
            };
            let response = self.build_allocate_response(msg, src_addr, lifetime, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Authentication check if credentials are configured
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

            // Validate MESSAGE-INTEGRITY
            let realm = msg.realm.as_deref().unwrap_or(&self.config.realm);
            let key = TurnAuth::compute_key(username, realm, password);

            if let (Some(integrity), Some(offset)) = (&msg.message_integrity, msg.message_integrity_offset) {
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

            // Valid credentials - create allocation
            let lifetime = 600;
            let alloc_id = self.allocations.create(src_addr, username.to_string(), lifetime);

            info!(
                "Created allocation {} for {} (user: {})",
                alloc_id, src_addr, username
            );

            let response = self.build_allocate_response(msg, src_addr, lifetime, Some(&key));
            debug!(
                "Sending Allocate response ({} bytes) to {}: {:02x?}",
                response.len(),
                src_addr,
                &response[..std::cmp::min(response.len(), 64)]
            );
            socket.send_to(&response, src_addr).await?;
        } else {
            // No authentication configured - anonymous access
            let username = msg.username.as_deref().unwrap_or("anonymous");

            let lifetime = 600;
            let alloc_id = self.allocations.create(src_addr, username.to_string(), lifetime);

            info!(
                "Created allocation {} for {} (user: {})",
                alloc_id, src_addr, username
            );

            let response = self.build_allocate_response(msg, src_addr, lifetime, None);
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

        // Compute auth key if request had MESSAGE-INTEGRITY
        let key = self.compute_response_key(msg, &alloc.username);

        // Parse requested lifetime (0 means delete allocation)
        let requested_lifetime = msg.lifetime.unwrap_or(600);

        if requested_lifetime == 0 {
            // Client wants to delete the allocation
            let alloc_id = alloc.id;
            drop(alloc); // Release the ref before removing
            self.allocations.remove(alloc_id);
            info!("Deleted allocation {} for {} (lifetime=0)", alloc_id, src_addr);

            let response = self.build_refresh_response(msg, 0, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Cap lifetime at 10 minutes max, minimum 60 seconds
        let lifetime = requested_lifetime.clamp(60, 600);
        alloc.refresh(lifetime);
        alloc.touch();

        debug!("Refreshed allocation for {} (lifetime={}s)", src_addr, lifetime);

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

        let (alloc_id, username, key) = {
            let alloc = match self.allocations.get_by_client(src_addr) {
                Some(a) => a,
                None => {
                    let response = self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            // Parse XOR-PEER-ADDRESS attributes (can have multiple)
            if msg.xor_peer_addresses.is_empty() {
                warn!("CreatePermission missing XOR-PEER-ADDRESS from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }

            let key = self.compute_response_key(msg, &alloc.username);
            alloc.touch();
            (alloc.id, alloc.username.clone(), key)
        };

        // Add permissions for each peer IP (must use table method to update index)
        for peer_addr in &msg.xor_peer_addresses {
            let peer_ip = peer_addr.ip();
            self.allocations.add_permission(alloc_id, peer_ip);
            debug!("Added permission for {} to allocation {}", peer_ip, alloc_id);
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
                    let response = self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            };

            let key = self.compute_response_key(msg, &alloc.username);
            let alloc_id = alloc.id;

            // Bind channel (this can be done while holding the ref)
            alloc.bind_channel(channel, peer_addr);
            alloc.touch();

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
                warn!("Send indication from unknown client: {}", src_addr);
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
                    socket.send_to(&indication, target_alloc.client_addr).await?;
                    sent = true;
                }
            }

            if !sent {
                warn!("No target allocation found for internal routing from {}", src_addr);
            }
            return Ok(());
        }

        // Get data
        let data = match &msg.data {
            Some(d) => d,
            None => {
                warn!("Send indication missing DATA from {}", src_addr);
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
        alloc.touch();

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
        self.append_xor_mapped_address(&mut response, client_addr);

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
        self.append_xor_relayed_address(&mut response, relay_addr);

        // XOR-MAPPED-ADDRESS
        self.append_xor_mapped_address(&mut response, client_addr);

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

    /// Compute auth key for response if request had MESSAGE-INTEGRITY
    fn compute_response_key(&self, msg: &StunInfo, username: &str) -> Option<[u8; 16]> {
        if msg.message_integrity.is_some() && !self.config.credentials.is_empty() {
            if let Some(password) = self.config.get_password(username) {
                let realm = msg.realm.as_deref().unwrap_or(&self.config.realm);
                return Some(TurnAuth::compute_key(username, realm, password));
            }
        }
        None
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

        // Padding
        while response.len() < 20 + padded_len {
            response.push(0);
        }

        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Append XOR-MAPPED-ADDRESS attribute
    fn append_xor_mapped_address(&self, buf: &mut Vec<u8>, addr: SocketAddr) {
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
            SocketAddr::V6(_v6) => {
                // TODO: IPv6 support
                unimplemented!("IPv6 not yet supported");
            }
        }
    }

    /// Append XOR-RELAYED-ADDRESS attribute
    fn append_xor_relayed_address(&self, buf: &mut Vec<u8>, addr: SocketAddr) {
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
            SocketAddr::V6(_) => unimplemented!("IPv6 not yet supported"),
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

        // Padding for ERROR-CODE
        while response.len() < 20 + padded_len {
            response.push(0);
        }

        // REALM attribute
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute
        let nonce = TurnAuth::generate_nonce();
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

        // Transaction ID (random for indication)
        packet.extend_from_slice(&[0; 12]);

        // XOR-PEER-ADDRESS attribute (0x0012)
        self.append_xor_peer_address(&mut packet, peer_addr);

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
    fn append_xor_peer_address(&self, buf: &mut Vec<u8>, addr: SocketAddr) {
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
            SocketAddr::V6(_) => unimplemented!("IPv6 not yet supported"),
        }
    }
}
