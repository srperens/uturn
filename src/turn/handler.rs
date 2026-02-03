//! TURN message handler

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::demux::StunInfo;
use crate::lookup::AllocationTable;

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
                self.handle_send(&msg, src_addr).await
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

    /// Handle TURN Allocate Request
    async fn handle_allocate(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        info!("Allocate request from {}", src_addr);

        // Check if already allocated
        if self.allocations.get_by_client(src_addr).is_some() {
            warn!("Allocation already exists for {}", src_addr);
            let response = self.build_error_response(
                msg,
                TurnErrorCode::AllocationMismatch,
            );
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // TODO: Proper authentication
        // For now, check if we have credentials configured
        let username = msg.username.as_deref().unwrap_or("anonymous");

        // Create allocation
        let lifetime = 600; // 10 minutes default
        let alloc_id = self.allocations.create(src_addr, username.to_string(), lifetime);

        info!(
            "Created allocation {} for {} (user: {})",
            alloc_id, src_addr, username
        );

        // Build success response
        let response = self.build_allocate_response(msg, src_addr, lifetime);
        socket.send_to(&response, src_addr).await?;

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

        // Parse requested lifetime (0 means delete allocation)
        let requested_lifetime = msg.lifetime.unwrap_or(600);

        if requested_lifetime == 0 {
            // Client wants to delete the allocation
            let alloc_id = alloc.id;
            drop(alloc); // Release the ref before removing
            self.allocations.remove(alloc_id);
            info!("Deleted allocation {} for {} (lifetime=0)", alloc_id, src_addr);

            let response = self.build_refresh_response(msg, 0);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Cap lifetime at 10 minutes max, minimum 60 seconds
        let lifetime = requested_lifetime.clamp(60, 600);
        alloc.refresh(lifetime);
        alloc.touch();

        debug!("Refreshed allocation for {} (lifetime={}s)", src_addr, lifetime);

        let response = self.build_refresh_response(msg, lifetime);
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

        let alloc_id = match self.allocations.lookup_by_source(src_addr) {
            Some(id) => id,
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

        // Add permissions for each peer IP
        for peer_addr in &msg.xor_peer_addresses {
            let peer_ip = peer_addr.ip();
            self.allocations.add_permission(alloc_id, peer_ip);
            debug!("Added permission for {} to allocation {}", peer_ip, alloc_id);
        }

        // Touch allocation to update activity
        if let Some(alloc) = self.allocations.get(alloc_id) {
            alloc.touch();
        }

        info!(
            "CreatePermission: added {} peer(s) for {} (alloc {})",
            msg.xor_peer_addresses.len(),
            src_addr,
            alloc_id
        );

        let response = self.build_success_response(msg);
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

        let alloc_id = match self.allocations.lookup_by_source(src_addr) {
            Some(id) => id,
            None => {
                let response = self.build_error_response(msg, TurnErrorCode::AllocationMismatch);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

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

        // Get allocation and bind the channel
        if let Some(alloc) = self.allocations.get(alloc_id) {
            // Also add permission for the peer IP (ChannelBind implies permission)
            alloc.add_permission(peer_addr.ip());
            alloc.bind_channel(channel, peer_addr);
            alloc.touch();

            info!(
                "ChannelBind: channel 0x{:04x} -> {} for {} (alloc {})",
                channel, peer_addr, src_addr, alloc_id
            );
        }

        let response = self.build_success_response(msg);
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Send Indication
    async fn handle_send(&self, _msg: &StunInfo, src_addr: SocketAddr) -> Result<()> {
        debug!("Send indication from {}", src_addr);

        // TODO: Parse XOR-PEER-ADDRESS and DATA from message
        // Relay data to peer

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
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

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

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a TURN Refresh Success Response
    fn build_refresh_response(&self, request: &StunInfo, lifetime: u32) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        // Message type: Refresh Success Response (0x0104)
        response.extend_from_slice(&[0x01, 0x04]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a generic success response
    fn build_success_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(20);

        // Success response: set bit 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let success_type = msg_type | 0x0100;

        response.extend_from_slice(&success_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // No attributes
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

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
}
