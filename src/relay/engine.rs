//! Media relay engine
//!
//! Handles forwarding of media packets between peers and clients.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::config::Config;
use crate::lookup::AllocationTable;

/// Media relay engine
pub struct RelayEngine {
    config: Arc<Config>,
    socket: Arc<UdpSocket>,
    allocations: Arc<AllocationTable>,
}

impl RelayEngine {
    /// Create a new relay engine
    pub fn new(
        config: Arc<Config>,
        socket: Arc<UdpSocket>,
        allocations: Arc<AllocationTable>,
    ) -> Self {
        Self {
            config,
            socket,
            allocations,
        }
    }

    /// Handle data from a peer
    ///
    /// When data arrives from a permitted peer, wrap it in Data Indication
    /// and send to the appropriate client.
    pub async fn handle_peer_data(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Find allocations that have permission for this peer
        let candidates = self.allocations.lookup_by_peer_ip(peer_addr.ip());
        if candidates.is_empty() {
            trace!("Data from unknown peer: {}", peer_addr);
            return Ok(());
        }

        // For single-port design with multiple clients permitted to the same peer,
        // we need to send to all matching allocations
        for alloc_id in candidates {
            let alloc = match self.allocations.get(alloc_id) {
                Some(a) => a,
                None => continue,
            };

            if !alloc.is_permitted(peer_addr.ip()) {
                continue;
            }

            debug!(
                "Relaying {} bytes from peer {} to client {} via Data Indication",
                data.len(),
                peer_addr,
                alloc.client_addr
            );

            // Check for channel binding (more efficient than Data indication)
            if let Some(channel) = alloc.channel_for_peer(peer_addr) {
                self.send_channel_data(channel, data, alloc.client_addr)
                    .await?;
            } else {
                self.send_data_indication(peer_addr, data, alloc.client_addr)
                    .await?;
            }

            alloc.touch();
        }

        Ok(())
    }

    /// Handle TURN ChannelData from client
    ///
    /// Client sends ChannelData to relay to a bound peer.
    pub async fn handle_channel_data(
        &self,
        channel: u16,
        data: &[u8],
        src_addr: SocketAddr,
    ) -> Result<()> {
        // Find allocation by client address
        let alloc = match self.allocations.get_by_client(src_addr) {
            Some(a) => a,
            None => {
                warn!("ChannelData from unknown client: {}", src_addr);
                return Ok(());
            }
        };

        // Find peer address for this channel
        let peer_addr = match alloc.peer_for_channel(channel) {
            Some(addr) => addr,
            None => {
                warn!(
                    "ChannelData for unbound channel {} from {}",
                    channel, src_addr
                );
                return Ok(());
            }
        };

        // Check permission
        if !alloc.is_permitted(peer_addr.ip()) {
            warn!("No permission for peer {} in allocation", peer_addr);
            return Ok(());
        }

        // Get relay address for single-port detection
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

        // Single-port TURN: if peer is the relay address, relay to other clients
        if peer_addr == relay_addr {
            debug!(
                "ChannelData to relay address - routing to other clients (channel {})",
                channel
            );

            // Find all other allocations that have permission for relay IP
            let candidates = self.allocations.lookup_by_peer_ip(self.config.external_ip);
            let mut relayed = false;

            for alloc_id in candidates {
                if let Some(target_alloc) = self.allocations.get(alloc_id) {
                    // Skip sender
                    if target_alloc.client_addr == src_addr {
                        continue;
                    }

                    // Check permission
                    if !target_alloc.is_permitted(self.config.external_ip) {
                        continue;
                    }

                    // Use reverse channel if available - skip clients without channel binding
                    // Data Indication to relay address doesn't work for WebRTC clients
                    // (they expect ChannelData for peers they have bound channels to)
                    if let Some(reverse_channel) = target_alloc.channel_for_peer(relay_addr) {
                        debug!(
                            "ChannelData relay: {} -> {} via reverse channel {}",
                            src_addr, target_alloc.client_addr, reverse_channel
                        );
                        self.send_channel_data(reverse_channel, data, target_alloc.client_addr)
                            .await?;
                        target_alloc.touch();
                        relayed = true;
                    } else {
                        // Client hasn't bound a channel to relay yet - skip
                        // They'll receive data once ChannelBind completes
                        trace!(
                            "Skipping {} - no channel binding to relay yet",
                            target_alloc.client_addr
                        );
                    }
                }
            }

            if relayed {
                alloc.touch_relay_success();
            } else {
                trace!("No target clients for ChannelData relay from {}", src_addr);
                alloc.touch_relay_attempt(); // Start orphan timer
            }
        }
        // Check if the peer is another TURN client on this server
        else if let Some(target_alloc) = self.allocations.get_by_client(peer_addr) {
            // Peer is another client - check if they have a channel bound back to sender
            if let Some(reverse_channel) = target_alloc.channel_for_peer(src_addr) {
                debug!(
                    "ChannelData relay: {} -> {} via channel {} (reverse channel {})",
                    src_addr, peer_addr, channel, reverse_channel
                );
                self.send_channel_data(reverse_channel, data, peer_addr)
                    .await?;
            } else {
                // No reverse channel, use Data Indication
                debug!(
                    "ChannelData relay: {} -> {} via Data Indication",
                    src_addr, peer_addr
                );
                self.send_data_indication(src_addr, data, peer_addr).await?;
            }
            target_alloc.touch();
        } else {
            // External peer - send raw data
            trace!(
                "Relaying {} bytes from client {} to external peer {} (channel {})",
                data.len(),
                src_addr,
                peer_addr,
                channel
            );
            self.socket.send_to(data, peer_addr).await?;
        }

        // Touch sender's allocation - they sent us data
        alloc.touch_received();
        Ok(())
    }

    /// Handle RTP packet from peer
    ///
    /// Peer sends RTP to relay address; forward to client.
    pub async fn handle_rtp(&self, ssrc: u32, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Try to find allocation by SSRC first (fast path after learning)
        let alloc_id = if let Some(id) = self.allocations.lookup_by_ssrc(ssrc) {
            id
        } else {
            // Fall back to permission-based lookup
            let candidates = self.allocations.lookup_by_peer_ip(peer_addr.ip());
            if candidates.is_empty() {
                trace!("RTP from unknown peer: {} (SSRC {:08x})", peer_addr, ssrc);
                return Ok(());
            }

            // If multiple allocations permit this peer, we need to disambiguate
            // For now, use the first one and register the SSRC
            let id = candidates[0];

            // Learn this SSRC for future fast lookups
            self.allocations.register_ssrc(id, ssrc);
            self.allocations.register_peer_tuple(id, peer_addr);

            debug!(
                "Learned SSRC {:08x} from {} -> allocation {}",
                ssrc, peer_addr, id
            );

            id
        };

        let alloc = match self.allocations.get(alloc_id) {
            Some(a) => a,
            None => return Ok(()),
        };

        // Check permission
        if !alloc.is_permitted(peer_addr.ip()) {
            return Ok(());
        }

        // Check for channel binding (more efficient than Data indication)
        if let Some(channel) = alloc.channel_for_peer(peer_addr) {
            self.send_channel_data(channel, data, alloc.client_addr)
                .await?;
        } else {
            self.send_data_indication(peer_addr, data, alloc.client_addr)
                .await?;
        }

        alloc.touch();

        Ok(())
    }

    /// Handle RTCP packet from peer
    pub async fn handle_rtcp(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // RTCP handling similar to RTP, but extract SSRC from RTCP header
        // For now, use permission-based lookup
        let candidates = self.allocations.lookup_by_peer_ip(peer_addr.ip());
        if candidates.is_empty() {
            trace!("RTCP from unknown peer: {}", peer_addr);
            return Ok(());
        }

        let alloc_id = candidates[0];
        let alloc = match self.allocations.get(alloc_id) {
            Some(a) => a,
            None => return Ok(()),
        };

        if !alloc.is_permitted(peer_addr.ip()) {
            return Ok(());
        }

        if let Some(channel) = alloc.channel_for_peer(peer_addr) {
            self.send_channel_data(channel, data, alloc.client_addr)
                .await?;
        } else {
            self.send_data_indication(peer_addr, data, alloc.client_addr)
                .await?;
        }

        Ok(())
    }

    /// Handle DTLS packet from peer
    pub async fn handle_dtls(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // DTLS handling - typically for SRTP key exchange
        let candidates = self.allocations.lookup_by_peer_ip(peer_addr.ip());
        if candidates.is_empty() {
            trace!("DTLS from unknown peer: {}", peer_addr);
            return Ok(());
        }

        let alloc_id = candidates[0];
        let alloc = match self.allocations.get(alloc_id) {
            Some(a) => a,
            None => return Ok(()),
        };

        if !alloc.is_permitted(peer_addr.ip()) {
            return Ok(());
        }

        // DTLS goes via Data indication (not ChannelData)
        self.send_data_indication(peer_addr, data, alloc.client_addr)
            .await?;

        Ok(())
    }

    /// Send TURN ChannelData to client
    async fn send_channel_data(
        &self,
        channel: u16,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        let mut packet = Vec::with_capacity(4 + data.len());

        // Channel number
        packet.extend_from_slice(&channel.to_be_bytes());

        // Length
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());

        // Data
        packet.extend_from_slice(data);

        // Pad to 4-byte boundary
        while packet.len() % 4 != 0 {
            packet.push(0);
        }

        self.socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    /// Send TURN Data Indication to client
    async fn send_data_indication(
        &self,
        peer_addr: SocketAddr,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
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

        self.socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    /// Append XOR-PEER-ADDRESS attribute
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
                for byte in addr_bytes.iter().skip(4) {
                    buf.push(*byte);
                }
            }
        }
    }
}
