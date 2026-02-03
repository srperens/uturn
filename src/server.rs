//! Main server implementation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

use crate::config::Config;
use crate::demux::{Demuxer, PacketType};
use crate::lookup::AllocationTable;
use crate::relay::RelayEngine;
use crate::turn::TurnHandler;

/// Maximum UDP packet size
const MAX_PACKET_SIZE: usize = 65535;

/// Interval for cleaning up expired allocations
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// uTURN server
pub struct Server {
    config: Arc<Config>,
    socket: Arc<UdpSocket>,
    allocations: Arc<AllocationTable>,
    turn_handler: Arc<TurnHandler>,
    relay_engine: Arc<RelayEngine>,
}

impl Server {
    /// Create a new server with the given configuration
    pub async fn new(config: Config) -> Result<Self> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
        let socket = UdpSocket::bind(bind_addr).await?;

        info!("Bound to {}", bind_addr);

        let config = Arc::new(config);
        let socket = Arc::new(socket);
        let allocations = Arc::new(AllocationTable::new());

        let turn_handler = Arc::new(TurnHandler::new(
            config.clone(),
            allocations.clone(),
        ));

        let relay_engine = Arc::new(RelayEngine::new(
            socket.clone(),
            allocations.clone(),
        ));

        Ok(Self {
            config,
            socket,
            allocations,
            turn_handler,
            relay_engine,
        })
    }

    /// Run the server main loop
    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        info!(
            "uTURN server running - relay address: {}:{}",
            self.config.external_ip, self.config.port
        );

        // Spawn cleanup task for expired allocations
        let cleanup_allocations = self.allocations.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let removed = cleanup_allocations.cleanup_expired();
                if removed > 0 {
                    info!("Cleaned up {} expired allocation(s)", removed);
                }
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
            };

            tokio::spawn(async move {
                if let Err(e) = server.handle_packet(&data, src_addr).await {
                    warn!("Error handling packet from {}: {}", src_addr, e);
                }
            });
        }
    }

    /// Handle a single incoming packet
    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        // Fast path: check if we have an allocation for this source
        if let Some(alloc_id) = self.allocations.lookup_by_source(src_addr) {
            trace!("Fast path: found allocation {} for {}", alloc_id, src_addr);
            // TODO: Handle based on packet type (relay or TURN control)
        }

        // Classify packet
        let packet_type = Demuxer::classify(data);

        match packet_type {
            PacketType::Stun(msg) => {
                debug!("STUN message from {}", src_addr);
                self.turn_handler.handle_stun(msg, src_addr, &self.socket).await?;
            }

            PacketType::TurnChannelData { channel, data } => {
                debug!("ChannelData (channel={}) from {}", channel, src_addr);
                self.relay_engine.handle_channel_data(channel, &data, src_addr).await?;
            }

            PacketType::Rtp { ssrc, data } => {
                trace!("RTP (SSRC={:08x}) from {}", ssrc, src_addr);
                self.relay_engine.handle_rtp(ssrc, &data, src_addr).await?;
            }

            PacketType::Rtcp(data) => {
                trace!("RTCP from {}", src_addr);
                self.relay_engine.handle_rtcp(&data, src_addr).await?;
            }

            PacketType::Dtls(data) => {
                trace!("DTLS from {}", src_addr);
                // DTLS is used for SRTP key exchange in WebRTC
                // For now, just relay it based on source tuple
                self.relay_engine.handle_dtls(&data, src_addr).await?;
            }

            PacketType::Unknown => {
                warn!("Unknown packet type from {} ({} bytes)", src_addr, data.len());
            }
        }

        Ok(())
    }
}
