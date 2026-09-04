//! Media relay engine
//!
//! Handles forwarding of media packets between peers and clients.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use crate::config::Config;
use crate::lookup::{AllocationId, AllocationTable};
use crate::turn::handler::is_forbidden_peer_addr;

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

/// Everything needed to deliver one packet to one client, captured while an
/// allocation guard is held and consumed only after that guard is released.
///
/// The relay paths await socket sends. An allocation guard (a DashMap shard
/// read lock) must never be held across those awaits: the cleanup task takes
/// shard write locks via `retain`, so a guard parked inside a suspended future
/// stalls cleanup and, on a single-worker runtime, deadlocks it. Every method
/// below therefore follows the same shape: snapshot under the guard, drop the
/// guard, then perform I/O against the snapshot.
#[derive(Debug, Clone, Copy)]
struct Delivery {
    id: AllocationId,
    client_addr: SocketAddr,
    /// Channel bound (from the receiver's perspective) to the packet's source,
    /// if any. `Some` selects ChannelData framing, `None` a Data Indication.
    channel: Option<u16>,
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

    /// Snapshot deliveries for peer traffic arriving from `peer_addr`.
    ///
    /// Skips allocations without permission for the peer IP and, when
    /// `skip_same_ip` is set, allocations whose client shares the peer's IP
    /// (avoids echoing traffic back to where it came from). When
    /// `use_channels` is set the receiver's channel binding for the peer is
    /// looked up; DTLS must always go via Data Indication so it passes false.
    fn snapshot_peer_deliveries(
        &self,
        candidates: &[AllocationId],
        peer_addr: SocketAddr,
        skip_same_ip: bool,
        use_channels: bool,
    ) -> Vec<Delivery> {
        candidates
            .iter()
            .filter_map(|&id| {
                let alloc = self.allocations.get(id)?;
                if !alloc.is_permitted(peer_addr.ip()) {
                    return None;
                }
                if skip_same_ip && alloc.client_addr.ip() == peer_addr.ip() {
                    trace!(
                        "Skipping {} - same IP as peer {}",
                        alloc.client_addr,
                        peer_addr
                    );
                    return None;
                }
                Some(Delivery {
                    id,
                    client_addr: alloc.client_addr,
                    channel: if use_channels {
                        alloc.channel_for_peer(peer_addr)
                    } else {
                        None
                    },
                })
            })
            .collect()
    }

    /// Send `data` to one snapshotted receiver, using ChannelData if a channel
    /// is bound, otherwise a Data Indication with `peer_addr` as the source.
    async fn deliver(&self, d: &Delivery, peer_addr: SocketAddr, data: &[u8]) -> Result<()> {
        match d.channel {
            Some(channel) => self.send_channel_data(channel, data, d.client_addr).await,
            None => {
                self.send_data_indication(peer_addr, data, d.client_addr)
                    .await
            }
        }
    }

    /// Re-acquire briefly to bump the activity timer (traffic TO the client).
    #[inline]
    fn touch(&self, id: AllocationId) {
        if let Some(a) = self.allocations.get(id) {
            a.touch();
        }
    }

    /// Re-acquire briefly to record the outcome of a relay attempt.
    #[inline]
    fn touch_relay(&self, id: AllocationId, relayed: bool) {
        if let Some(a) = self.allocations.get(id) {
            if relayed {
                a.touch_relay_success();
            } else {
                a.touch_relay_attempt();
            }
        }
    }

    /// Snapshot the sender's (local, remote) ICE ufrags.
    fn sender_ufrags(&self, id: AllocationId) -> (Option<String>, Option<String>) {
        match self.allocations.get(id) {
            Some(a) => (a.get_ice_ufrag(), a.get_ice_remote_ufrag()),
            None => (None, None),
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

        let deliveries = self.snapshot_peer_deliveries(&candidates, peer_addr, true, true);
        for d in deliveries {
            debug!(
                "Relaying {} bytes from peer {} to client {} via {}",
                data.len(),
                peer_addr,
                d.client_addr,
                if d.channel.is_some() {
                    "ChannelData"
                } else {
                    "Data Indication"
                }
            );
            self.deliver(&d, peer_addr, data).await?;
            self.touch(d.id);
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

        // Snapshot the sender's id, the bound peer and the permission check,
        // then release the guard before anything below awaits.
        let (alloc_id, peer_addr, permitted) = match self.allocations.get_by_client(src_addr) {
            Some(alloc) => match alloc.peer_for_channel(channel) {
                Some(peer) => (alloc.id, peer, alloc.is_permitted(peer.ip())),
                None => {
                    trace!(
                        "ChannelData for unbound channel {} from {}",
                        channel,
                        src_addr
                    );
                    return Ok(());
                }
            },
            None => {
                trace!("ChannelData from unknown client: {}", src_addr);
                return Ok(());
            }
        };

        if !permitted {
            trace!("No permission for peer {} in allocation", peer_addr);
            return Ok(());
        }

        // Get relay address for single-port detection
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

        // Single-port TURN: if peer is the relay address, relay to other clients
        if peer_addr == relay_addr {
            // Check if this is STUN (ICE connectivity check)
            if is_stun(data) {
                let mut sent = false;

                // Try 1: Targeted send via USERNAME attribute (STUN Binding Requests)
                if let Some((remote_ufrag, local_ufrag)) = extract_stun_ufrags(data) {
                    // Register sender's ICE ufrags for future lookups
                    let registered = self.allocations.register_ice_ufrags(
                        alloc_id,
                        local_ufrag.clone(),
                        remote_ufrag.clone(),
                    );

                    if registered {
                        debug!(
                            "ICE registration: {} local_ufrag={}, remote_ufrag={}",
                            src_addr, local_ufrag, remote_ufrag
                        );
                    }

                    // Forward to target by their ICE ufrag: snapshot, release, send.
                    let target = self
                        .allocations
                        .lookup_by_ice_ufrag(&remote_ufrag)
                        .and_then(|target_id| {
                            let t = self.allocations.get(target_id)?;
                            if t.client_addr == src_addr {
                                return None;
                            }
                            Some(Delivery {
                                id: target_id,
                                client_addr: t.client_addr,
                                channel: t.channel_for_peer(relay_addr),
                            })
                        });
                    if let Some(d) = target {
                        self.deliver(&d, relay_addr, data).await?;
                        self.touch(d.id);
                        sent = true;
                    }
                }

                // Try 2: ICE peer matching (for STUN responses without USERNAME).
                // Read the sender's ufrags fresh - Try 1 may have just set them.
                if !sent {
                    let (sender_local, sender_remote) = self.sender_ufrags(alloc_id);
                    if let (Some(local), Some(remote)) = (&sender_local, &sender_remote) {
                        let peers = self.allocations.find_ice_peers(local, remote);
                        if !peers.is_empty()
                            && self
                                .relay_to_listeners(data, src_addr, &peers, relay_addr)
                                .await?
                        {
                            sent = true;
                        }
                    }
                }

                // No broadcast fallback - ufrags are registered via Send Indication
                // before channel binding, so ufrag routing should always work here.
                if !sent {
                    trace!(
                        "STUN via ChannelData from {} dropped: no ufrag match",
                        src_addr,
                    );
                }
            } else {
                // Media (RTP) and non-media (DTLS/RTCP) both use bi-directional ICE
                // ufrag matching: if sender has (local=X, remote=Y), find allocations
                // with (local=Y, remote=X). No broadcast fallback for either.
                let is_rtp = is_rtp(data);
                let (sender_local, sender_remote) = self.sender_ufrags(alloc_id);

                let peers = match (&sender_local, &sender_remote) {
                    (Some(local), Some(remote)) => self.allocations.find_ice_peers(local, remote),
                    _ => Vec::new(),
                };

                if is_rtp {
                    // Debug: log occasionally
                    static COUNTER: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
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
                }

                if peers.is_empty() {
                    trace!(
                        "{} ChannelData from {} ({} bytes) dropped: no ICE ufrag match \
                         (local={:?}, remote={:?})",
                        if is_rtp { "RTP" } else { "Non-RTP" },
                        src_addr,
                        data.len(),
                        sender_local,
                        sender_remote,
                    );
                    self.touch_relay(alloc_id, false);
                } else {
                    let relayed = self
                        .relay_to_listeners(data, src_addr, &peers, relay_addr)
                        .await?;
                    self.touch_relay(alloc_id, relayed);
                }
            }
        } else {
            // Is the peer another TURN client on this server? Snapshot its id
            // and reverse channel, release the guard, then send.
            let target = self.allocations.get_by_client(peer_addr).map(|t| Delivery {
                id: t.id,
                client_addr: t.client_addr,
                channel: t.channel_for_peer(src_addr),
            });

            if let Some(d) = target {
                debug!(
                    "ChannelData relay: {} -> {} via channel {} ({})",
                    src_addr,
                    peer_addr,
                    channel,
                    match d.channel {
                        Some(rc) => format!("reverse channel 0x{:04x}", rc),
                        None => "Data Indication".to_string(),
                    }
                );
                self.deliver(&d, src_addr, data).await?;
                self.touch(d.id);
            } else {
                // External peer - send raw data. Defense-in-depth: handle_channel_bind
                // already rejects forbidden peer IPs, so this branch should only hit
                // legitimate destinations. If a forbidden peer ever reaches here, drop.
                if is_forbidden_peer_addr(&self.config, peer_addr) {
                    trace!(
                        "ChannelData to forbidden peer {} from {} dropped",
                        peer_addr,
                        src_addr
                    );
                    return Ok(());
                }
                trace!(
                    "Relaying {} bytes from client {} to external peer {} (channel {})",
                    data.len(),
                    src_addr,
                    peer_addr,
                    channel
                );
                self.socket.send_to(data, peer_addr).await?;
            }
        }

        // Touch sender's allocation - they sent us data
        if let Some(a) = self.allocations.get(alloc_id) {
            a.touch_received();
        }
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

        let deliveries = if is_unique {
            // Unique match (tuple hit or single IP match): register tuple for
            // fast path on future packets. No same-IP skip on this path.
            self.allocations
                .register_peer_tuple(candidates[0], peer_addr);
            self.snapshot_peer_deliveries(&candidates, peer_addr, false, true)
        } else {
            // Multiple IP candidates and no tuple registered yet:
            // send to all on first packet, but don't register anything.
            trace!(
                "RTP from {} (SSRC {:08x}) - {} candidates, sending to all (first packet)",
                peer_addr,
                ssrc,
                candidates.len()
            );
            self.snapshot_peer_deliveries(&candidates, peer_addr, true, true)
        };

        for d in deliveries {
            self.deliver(&d, peer_addr, data).await?;
            self.touch(d.id);
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

        let deliveries = self.snapshot_peer_deliveries(&candidates, peer_addr, true, true);
        for d in deliveries {
            self.deliver(&d, peer_addr, data).await?;
            self.touch(d.id);
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

        // DTLS goes via Data Indication (not ChannelData): use_channels = false.
        let deliveries = self.snapshot_peer_deliveries(&candidates, peer_addr, true, false);
        for d in deliveries {
            self.deliver(&d, peer_addr, data).await?;
            self.touch(d.id);
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
        // Snapshot every target under its own short-lived guard, then send.
        let deliveries: Vec<Delivery> = listeners
            .iter()
            .filter_map(|&id| {
                let t = self.allocations.get(id)?;
                // Skip sender (exact match only - same IP and port). We allow
                // relaying to same IP different port (e.g., two browser tabs).
                if t.client_addr == src_addr {
                    return None;
                }
                Some(Delivery {
                    id,
                    client_addr: t.client_addr,
                    // Use reverse channel if available, fall back to Data Indication
                    channel: t.channel_for_peer(relay_addr),
                })
            })
            .collect();

        let mut relayed = false;
        for d in deliveries {
            self.deliver(&d, relay_addr, data).await?;
            self.touch(d.id);
            relayed = true;
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
