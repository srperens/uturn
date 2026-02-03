//! Main server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, trace, warn};

use crate::config::Config;
use crate::demux::{Demuxer, PacketType};
use crate::lookup::{AllocationTable, RateLimiter};
use crate::relay::RelayEngine;
use crate::turn::TurnHandler;

/// Maximum UDP packet size
const MAX_PACKET_SIZE: usize = 65535;

/// Interval for cleaning up expired allocations
const CLEANUP_INTERVAL_SECS: u64 = 10;

/// Inactivity timeout - remove allocation if no traffic FROM client for this long
const INACTIVITY_TIMEOUT_SECS: u64 = 30;

/// uTURN server
pub struct Server {
    config: Arc<Config>,
    socket: Arc<UdpSocket>,
    allocations: Arc<AllocationTable>,
    turn_handler: Arc<TurnHandler>,
    relay_engine: Arc<RelayEngine>,
    rate_limiter: Arc<RateLimiter>,
    task_semaphore: Option<Arc<Semaphore>>,
}

impl Server {
    /// Create a new server with the given configuration
    pub async fn new(config: Config) -> Result<Self> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
        let socket = UdpSocket::bind(bind_addr).await?;

        info!("Bound to {}", bind_addr);

        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_per_minute,
            config.max_allocations_per_ip,
        ));

        let task_semaphore = if config.max_concurrent_tasks > 0 {
            Some(Arc::new(Semaphore::new(
                config.max_concurrent_tasks as usize,
            )))
        } else {
            None
        };

        let config = Arc::new(config);
        let socket = Arc::new(socket);
        let allocations = Arc::new(AllocationTable::new());

        let turn_handler = Arc::new(TurnHandler::new(
            config.clone(),
            allocations.clone(),
            rate_limiter.clone(),
        ));

        let relay_engine = Arc::new(RelayEngine::new(
            config.clone(),
            socket.clone(),
            allocations.clone(),
        ));

        Ok(Self {
            config,
            socket,
            allocations,
            turn_handler,
            relay_engine,
            rate_limiter,
            task_semaphore,
        })
    }

    /// Run the server main loop
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        info!(
            "uTURN server running - relay address: {}:{}",
            self.config.external_ip, self.config.port
        );

        // Spawn cleanup task for expired, inactive, and orphaned allocations
        let cleanup_allocations = self.allocations.clone();
        let cleanup_rate_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;

                // Cleanup expired allocations and update quota
                let expired_ips = cleanup_allocations.cleanup_expired();
                if !expired_ips.is_empty() {
                    info!("Cleaned up {} expired allocation(s)", expired_ips.len());
                    for ip in expired_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Cleanup inactive allocations and update quota
                let inactive_ips = cleanup_allocations.cleanup_inactive(INACTIVITY_TIMEOUT_SECS);
                if !inactive_ips.is_empty() {
                    info!("Cleaned up {} inactive allocation(s)", inactive_ips.len());
                    for ip in inactive_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Cleanup orphaned senders and update quota
                let orphaned_ips =
                    cleanup_allocations.cleanup_orphaned_senders(INACTIVITY_TIMEOUT_SECS);
                if !orphaned_ips.is_empty() {
                    info!(
                        "Cleaned up {} orphaned sender allocation(s)",
                        orphaned_ips.len()
                    );
                    for ip in orphaned_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Cleanup stale rate limiter entries
                cleanup_rate_limiter.cleanup();
            }
        });

        loop {
            let (len, src_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to receive packet: {}", e);
                    continue;
                }
            };

            let data = buf[..len].to_vec();
            trace!("Received {} bytes from {}", len, src_addr);

            // Spawn task to handle packet
            let server = Server {
                config: self.config.clone(),
                socket: self.socket.clone(),
                allocations: self.allocations.clone(),
                turn_handler: self.turn_handler.clone(),
                relay_engine: self.relay_engine.clone(),
                rate_limiter: self.rate_limiter.clone(),
                task_semaphore: self.task_semaphore.clone(),
            };

            // Acquire semaphore permit for backpressure (if configured)
            let permit = match &self.task_semaphore {
                Some(sem) => match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        // At capacity - drop packet to prevent unbounded growth
                        warn!("Task queue at capacity, dropping packet from {}", src_addr);
                        continue;
                    }
                },
                None => None,
            };

            tokio::spawn(async move {
                // Hold permit until task completes
                let _permit = permit;
                if let Err(e) = server.handle_packet(&data, src_addr).await {
                    warn!("Error handling packet from {}: {}", src_addr, e);
                }
            });
        }
    }

    /// Handle a single incoming packet
    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        // Check if this is from a client (has an allocation at this address)
        // Important: is_client checks by_client only, NOT by_peer_tuple
        // This prevents learned peer tuples from being treated as clients
        let is_client = self.allocations.is_client(src_addr);
        if is_client {
            trace!("Fast path: found allocation for client {}", src_addr);
        }

        // Classify packet FIRST - this is important!
        // We must classify before checking peer permissions, because a new client
        // from the same IP (different port) could be sending a STUN Allocate request.
        let packet_type = Demuxer::classify(data);

        match packet_type {
            PacketType::Stun(msg) => {
                // STUN messages are ALWAYS processed by the TURN handler.
                // This includes new Allocate requests from any source.
                debug!("STUN message from {}", src_addr);
                self.turn_handler
                    .handle_stun(msg, src_addr, &self.socket)
                    .await?;
            }

            PacketType::TurnChannelData { channel, data } => {
                debug!("ChannelData (channel={}) from {}", channel, src_addr);
                self.relay_engine
                    .handle_channel_data(channel, &data, src_addr)
                    .await?;
            }

            PacketType::Rtp { ssrc, data } => {
                if is_client {
                    // Client sending RTP - relay to other clients (single-port TURN)
                    debug!("RTP from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    // Check if this is from a permitted peer
                    let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());
                    if !candidates.is_empty() {
                        // Use SSRC-aware routing to disambiguate when multiple clients
                        // permit the same peer IP
                        debug!(
                            "RTP from peer {} (SSRC={:08x}) - relaying with SSRC routing",
                            src_addr, ssrc
                        );
                        self.relay_engine.handle_rtp(ssrc, &data, src_addr).await?;
                    } else {
                        trace!("RTP (SSRC={:08x}) from unknown {}", ssrc, src_addr);
                    }
                }
            }

            PacketType::Rtcp(data) => {
                if is_client {
                    debug!("RTCP from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());
                    if !candidates.is_empty() {
                        debug!("RTCP from peer {} - relaying", src_addr);
                        self.relay_engine.handle_rtcp(&data, src_addr).await?;
                    } else {
                        trace!("RTCP from unknown {}", src_addr);
                    }
                }
            }

            PacketType::Dtls(data) => {
                if is_client {
                    // Client sending DTLS (handshake) - relay to other clients
                    debug!("DTLS from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());
                    if !candidates.is_empty() {
                        debug!("DTLS from peer {} - relaying via Data Indication", src_addr);
                        self.relay_engine.handle_peer_data(&data, src_addr).await?;
                    } else {
                        trace!("DTLS from unknown {}", src_addr);
                    }
                }
            }

            PacketType::Unknown => {
                if is_client {
                    debug!(
                        "Unknown data from client {} - relaying to other clients",
                        src_addr
                    );
                    self.relay_client_data(data, src_addr).await?;
                } else {
                    let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());
                    if !candidates.is_empty() {
                        debug!(
                            "Unknown data from peer {} - relaying via Data Indication",
                            src_addr
                        );
                        self.relay_engine.handle_peer_data(data, src_addr).await?;
                    } else {
                        warn!(
                            "Unknown packet type from {} ({} bytes)",
                            src_addr,
                            data.len()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Relay data from one client to other clients (single-port TURN)
    ///
    /// In single-port TURN, all clients share the same relay address. When client A
    /// sends data to the server, we relay it to other clients that have permission
    /// for the relay IP. The Data indication uses XOR-PEER-ADDRESS = relay address,
    /// because from the receiver's perspective, the peer is at the relay address.
    async fn relay_client_data(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

        // Get sender's allocation for tracking relay success
        let sender_alloc = self.allocations.get_by_client(src_addr);

        // Find all allocations that have permission for our relay IP
        let candidates = self.allocations.lookup_by_peer_ip(self.config.external_ip);

        let mut relayed = false;
        for alloc_id in candidates {
            if let Some(target_alloc) = self.allocations.get(alloc_id) {
                // Skip the sender's own allocation
                if target_alloc.client_addr == src_addr {
                    continue;
                }

                // Check that target has permission for relay IP
                if !target_alloc.is_permitted(self.config.external_ip) {
                    continue;
                }

                debug!(
                    "Relaying {} bytes from client {} to client {} (via relay {})",
                    data.len(),
                    src_addr,
                    target_alloc.client_addr,
                    relay_addr
                );

                // Build and send Data indication
                // XOR-PEER-ADDRESS = relay address (peer from receiver's perspective)
                let indication = self.build_data_indication(relay_addr, data);
                self.socket
                    .send_to(&indication, target_alloc.client_addr)
                    .await?;
                target_alloc.touch();
                relayed = true;
            }
        }

        // Track relay success/failure for orphan detection
        if let Some(alloc) = sender_alloc {
            if relayed {
                alloc.touch_relay_success();
            } else {
                alloc.touch_relay_attempt();
            }
        }

        if !relayed {
            trace!("No target clients found for relay from {}", src_addr);
        }

        Ok(())
    }

    /// Build a TURN Data Indication message
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
        self.append_xor_peer_address(&mut packet, peer_addr);

        // DATA attribute (0x0013)
        packet.extend_from_slice(&[0x00, 0x13]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad DATA attribute to 4-byte boundary
        while (packet.len() - 20) % 4 != 0 {
            packet.push(0);
        }

        // Update length field
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        packet
    }

    /// Append XOR-PEER-ADDRESS attribute to buffer
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
