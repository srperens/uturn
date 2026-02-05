//! Media relay engine
//!
//! Handles forwarding of media packets between peers and clients.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use crate::config::Config;
use crate::lookup::{Allocation, AllocationId, AllocationTable};

/// Check if data looks like RTP (vs RTCP)
/// Check if data is DTLS (content types 0x14-0x19, version 0xFExx)
fn is_dtls(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    // DTLS content types: 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake,
    // 0x17=ApplicationData, 0x18-0x19=Heartbeat
    let content_type = data[0];
    if !(0x14..=0x19).contains(&content_type) {
        return false;
    }
    // DTLS version starts with 0xFE (1.0=0xFEFF, 1.2=0xFEFD)
    data[1] == 0xFE
}

fn is_rtp(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    // DTLS should not be classified as RTP
    if is_dtls(data) {
        return false;
    }
    // RTP payload types 0-34, 96-127 are common
    // RTCP payload types are 200-204
    let pt = data[1] & 0x7F;
    !(64..96).contains(&pt)
}

/// Check if data is a STUN message (first byte 0-3, magic cookie at bytes 4-7)
fn is_stun(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // STUN messages start with 0b00 in first two bits
    if (data[0] >> 6) != 0 {
        return false;
    }
    // Magic cookie at bytes 4-7 must be 0x2112A442
    data[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

/// Extract both ufrags from STUN Binding Request USERNAME attribute
/// USERNAME format is "remoteUfrag:localUfrag"
/// Returns (remote_ufrag, local_ufrag) - remote is who they want to talk to, local is sender's ufrag
fn extract_stun_ufrags(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 20 {
        return None;
    }

    // STUN header is 20 bytes, attributes follow
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return None;
    }

    let mut offset = 20;
    while offset + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if offset + 4 + attr_len > data.len() {
            break;
        }

        // USERNAME attribute type is 0x0006
        if attr_type == 0x0006 {
            let username_bytes = &data[offset + 4..offset + 4 + attr_len];
            if let Ok(username) = std::str::from_utf8(username_bytes) {
                // Format is "remoteUfrag:localUfrag"
                if let Some(colon_pos) = username.find(':') {
                    let remote = username[..colon_pos].to_string();
                    let local = username[colon_pos + 1..].to_string();
                    return Some((remote, local));
                }
            }
        }

        // Move to next attribute (4-byte aligned)
        offset += 4 + ((attr_len + 3) & !3);
    }

    None
}

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
        // Find allocations - prefer tuple lookup, fallback to IP
        let (candidates, is_unique) = self.allocations.lookup_by_peer_addr(peer_addr);
        if candidates.is_empty() {
            trace!("Data from unknown peer: {}", peer_addr);
            return Ok(());
        }

        // If unique match, register tuple for fast path on future packets
        if is_unique {
            self.allocations
                .register_peer_tuple(candidates[0], peer_addr);
        }

        for alloc_id in candidates {
            let alloc = match self.allocations.get(alloc_id) {
                Some(a) => a,
                None => continue,
            };

            if !alloc.is_permitted(peer_addr.ip()) {
                continue;
            }

            // Don't echo data back to the same IP it came from
            if alloc.client_addr.ip() == peer_addr.ip() {
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
        trace!(
            "ChannelData ch=0x{:04x} from {} ({} bytes, first byte: 0x{:02x})",
            channel,
            src_addr,
            data.len(),
            data.first().copied().unwrap_or(0)
        );

        // Find allocation by client address
        let alloc = match self.allocations.get_by_client(src_addr) {
            Some(a) => a,
            None => {
                trace!("ChannelData from unknown client: {}", src_addr);
                return Ok(());
            }
        };

        // Find peer address for this channel
        let peer_addr = match alloc.peer_for_channel(channel) {
            Some(addr) => addr,
            None => {
                trace!(
                    "ChannelData for unbound channel {} from {}",
                    channel,
                    src_addr
                );
                return Ok(());
            }
        };

        // Check permission
        if !alloc.is_permitted(peer_addr.ip()) {
            trace!("No permission for peer {} in allocation", peer_addr);
            return Ok(());
        }

        // Get relay address for single-port detection
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

        // Single-port TURN: if peer is the relay address, relay to other clients
        if peer_addr == relay_addr {
            // Check if this is STUN (ICE connectivity check)
            if is_stun(data) {
                // STUN Binding Request - extract both ufrags for pairing and forwarding
                // USERNAME format is "remoteUfrag:localUfrag"
                // - remote_ufrag = who sender wants to talk to (receiver's ICE ufrag)
                // - local_ufrag = sender's own ICE ufrag
                if let Some((remote_ufrag, local_ufrag)) = extract_stun_ufrags(data) {
                    // Register both local and remote ICE ufrags for this allocation
                    // local_ufrag = this client's ufrag, remote_ufrag = peer they want to talk to
                    let registered = self.allocations.register_ice_ufrags(
                        alloc.id,
                        local_ufrag.clone(),
                        remote_ufrag.clone(),
                    );

                    if registered {
                        debug!(
                            "ICE registration: {} (client={}) local_ufrag={}, remote_ufrag={}",
                            src_addr, alloc.client_addr, local_ufrag, remote_ufrag
                        );
                    }

                    // Forward STUN to the target allocation (if we can find it by ICE ufrag)
                    if let Some(target_id) = self.allocations.lookup_by_ice_ufrag(&remote_ufrag) {
                        if let Some(target_alloc) = self.allocations.get(target_id) {
                            if let Some(reverse_channel) = target_alloc.channel_for_peer(relay_addr)
                            {
                                self.send_channel_data(
                                    reverse_channel,
                                    data,
                                    target_alloc.client_addr,
                                )
                                .await?;
                                target_alloc.touch();
                            }
                        }
                    }
                }
                // Also broadcast STUN for ICE to work properly
                self.relay_to_all_except_sender(data, src_addr, &alloc, relay_addr)
                    .await?;
            } else if !is_rtp(data) {
                // Non-RTP (DTLS/RTCP) - always broadcast to all clients with relay permission
                // DTLS handshake may start before ICE ufrags are registered, so we can't
                // rely on ufrag-based routing. Broadcasting is safe because DTLS will only
                // succeed with the correct peer (certificate fingerprint matching).
                debug!(
                    "Non-RTP ChannelData from {} ({} bytes) - broadcasting to all",
                    src_addr,
                    data.len()
                );
                self.relay_to_all_except_sender(data, src_addr, &alloc, relay_addr)
                    .await?;
            } else {
                // RTP - use bi-directional ICE ufrag matching
                // If sender has (local=X, remote=Y), find allocations with (local=Y, remote=X)
                let sender_local = alloc.get_ice_ufrag();
                let sender_remote = alloc.get_ice_remote_ufrag();

                let peers = match (&sender_local, &sender_remote) {
                    (Some(local), Some(remote)) => self.allocations.find_ice_peers(local, remote),
                    _ => Vec::new(),
                };

                // Debug: log occasionally
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                #[allow(clippy::manual_is_multiple_of)]
                if count % 1000 == 0 {
                    debug!(
                        "RTP from {} (local={:?}, remote={:?}), {} ICE peers",
                        src_addr,
                        sender_local,
                        sender_remote,
                        peers.len()
                    );
                }

                if !peers.is_empty() {
                    // Route to ICE peer allocations only
                    let relayed = self
                        .relay_to_listeners(data, src_addr, &peers, relay_addr)
                        .await?;
                    if relayed {
                        alloc.touch_relay_success();
                    } else {
                        alloc.touch_relay_attempt();
                    }
                } else {
                    // No ICE peers found - broadcast (fallback)
                    self.relay_to_all_except_sender(data, src_addr, &alloc, relay_addr)
                        .await?;
                }
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
    /// Uses tuple-based routing for efficiency when peer tuple is registered.
    pub async fn handle_rtp(&self, ssrc: u32, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Prefer tuple lookup, fallback to IP-based
        let (candidates, is_unique) = self.allocations.lookup_by_peer_addr(peer_addr);
        if candidates.is_empty() {
            trace!("RTP from unknown peer: {} (SSRC {:08x})", peer_addr, ssrc);
            return Ok(());
        }

        // If unique match (tuple hit or single IP match), use fast path
        if is_unique {
            let alloc_id = candidates[0];

            // Register tuple for fast path on future packets
            self.allocations.register_peer_tuple(alloc_id, peer_addr);

            if let Some(alloc) = self.allocations.get(alloc_id) {
                if alloc.is_permitted(peer_addr.ip()) {
                    if let Some(channel) = alloc.channel_for_peer(peer_addr) {
                        self.send_channel_data(channel, data, alloc.client_addr)
                            .await?;
                    } else {
                        self.send_data_indication(peer_addr, data, alloc.client_addr)
                            .await?;
                    }
                    alloc.touch();
                }
            }
        } else {
            // Multiple IP candidates and no tuple registered yet
            // Send to all on first packet, but don't register anything
            trace!(
                "RTP from {} (SSRC {:08x}) - {} candidates, sending to all (first packet)",
                peer_addr,
                ssrc,
                candidates.len()
            );

            for alloc_id in candidates {
                let alloc = match self.allocations.get(alloc_id) {
                    Some(a) => a,
                    None => continue,
                };

                if !alloc.is_permitted(peer_addr.ip()) {
                    continue;
                }

                // Don't echo data back to the same IP it came from
                if alloc.client_addr.ip() == peer_addr.ip() {
                    trace!(
                        "Skipping {} - same IP as peer {}",
                        alloc.client_addr,
                        peer_addr
                    );
                    continue;
                }

                if let Some(channel) = alloc.channel_for_peer(peer_addr) {
                    self.send_channel_data(channel, data, alloc.client_addr)
                        .await?;
                } else {
                    self.send_data_indication(peer_addr, data, alloc.client_addr)
                        .await?;
                }

                alloc.touch();
            }
        }

        Ok(())
    }

    /// Handle RTCP packet from peer
    ///
    /// Uses tuple-based routing for efficiency when peer tuple is registered.
    pub async fn handle_rtcp(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Prefer tuple lookup, fallback to IP-based
        let (candidates, is_unique) = self.allocations.lookup_by_peer_addr(peer_addr);
        if candidates.is_empty() {
            trace!("RTCP from unknown peer: {}", peer_addr);
            return Ok(());
        }

        // If unique match, register tuple for fast path
        if is_unique {
            self.allocations
                .register_peer_tuple(candidates[0], peer_addr);
        }

        for alloc_id in candidates {
            let alloc = match self.allocations.get(alloc_id) {
                Some(a) => a,
                None => continue,
            };

            if !alloc.is_permitted(peer_addr.ip()) {
                continue;
            }

            // Don't echo data back to the same IP it came from
            if alloc.client_addr.ip() == peer_addr.ip() {
                continue;
            }

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

    /// Handle DTLS packet from peer
    ///
    /// Uses tuple-based routing for efficiency when peer tuple is registered.
    pub async fn handle_dtls(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // Prefer tuple lookup, fallback to IP-based
        let (candidates, is_unique) = self.allocations.lookup_by_peer_addr(peer_addr);
        if candidates.is_empty() {
            trace!("DTLS from unknown peer: {}", peer_addr);
            return Ok(());
        }

        // If unique match, register tuple for fast path
        if is_unique {
            self.allocations
                .register_peer_tuple(candidates[0], peer_addr);
        }

        for alloc_id in candidates {
            let alloc = match self.allocations.get(alloc_id) {
                Some(a) => a,
                None => continue,
            };

            if !alloc.is_permitted(peer_addr.ip()) {
                continue;
            }

            // Don't echo data back to the same IP it came from
            if alloc.client_addr.ip() == peer_addr.ip() {
                continue;
            }

            // DTLS goes via Data indication (not ChannelData)
            self.send_data_indication(peer_addr, data, alloc.client_addr)
                .await?;

            alloc.touch();
        }

        Ok(())
    }

    /// Relay data to all clients except the sender (broadcast mode)
    async fn relay_to_all_except_sender(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
        sender_alloc: &Allocation,
        relay_addr: SocketAddr,
    ) -> Result<()> {
        let candidates = self.allocations.lookup_by_peer_ip(self.config.external_ip);
        let mut relayed = false;

        for alloc_id in candidates {
            if let Some(target_alloc) = self.allocations.get(alloc_id) {
                // Skip sender (exact match only - same IP and port)
                if target_alloc.client_addr == src_addr {
                    continue;
                }
                // Note: We allow relaying to same IP different port (e.g., two browser tabs)
                // Check permission
                if !target_alloc.is_permitted(self.config.external_ip) {
                    continue;
                }
                // Use reverse channel if available
                if let Some(reverse_channel) = target_alloc.channel_for_peer(relay_addr) {
                    self.send_channel_data(reverse_channel, data, target_alloc.client_addr)
                        .await?;
                    target_alloc.touch();
                    relayed = true;
                }
            }
        }

        if relayed {
            sender_alloc.touch_relay_success();
        } else {
            sender_alloc.touch_relay_attempt();
        }

        Ok(())
    }

    /// Relay data to specific listeners (ufrag-paired routing)
    /// Returns true if data was sent to at least one target
    async fn relay_to_listeners(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
        listeners: &[AllocationId],
        relay_addr: SocketAddr,
    ) -> Result<bool> {
        let mut relayed = false;
        for &alloc_id in listeners {
            if let Some(target_alloc) = self.allocations.get(alloc_id) {
                // Skip sender (exact match only - same IP and port)
                if target_alloc.client_addr == src_addr {
                    continue;
                }
                // Note: We allow relaying to same IP different port (e.g., two browser tabs)
                // Use reverse channel if available
                if let Some(reverse_channel) = target_alloc.channel_for_peer(relay_addr) {
                    self.send_channel_data(reverse_channel, data, target_alloc.client_addr)
                        .await?;
                    target_alloc.touch();
                    relayed = true;
                }
            }
        }
        Ok(relayed)
    }

    /// Send TURN ChannelData to client
    #[inline]
    async fn send_channel_data(
        &self,
        channel: u16,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        // Pre-calculate padded size
        let padding = (4 - ((4 + data.len()) % 4)) % 4;
        let mut packet = Vec::with_capacity(4 + data.len() + padding);

        // Channel number
        packet.extend_from_slice(&channel.to_be_bytes());

        // Length
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());

        // Data
        packet.extend_from_slice(data);

        // Pad to 4-byte boundary (more efficient than byte-by-byte)
        packet.resize(packet.len() + padding, 0);

        self.socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    /// Send TURN Data Indication to client
    #[inline]
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
        self.append_xor_peer_address(&mut packet, peer_addr, &txn_id);

        // DATA attribute (0x0013)
        packet.extend_from_slice(&[0x00, 0x13]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad DATA attribute to 4-byte boundary
        let padding = (4 - ((packet.len() - 20) % 4)) % 4;
        packet.resize(packet.len() + padding, 0);

        // Update length
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        self.socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    /// Append XOR-PEER-ADDRESS attribute
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
}
