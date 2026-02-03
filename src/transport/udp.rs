//! UDP transport

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;

/// UDP transport configuration
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    external_ip: IpAddr,
    port: u16,
}

impl UdpTransport {
    /// Create a new UDP transport bound to the specified port
    pub async fn bind(port: u16, external_ip: IpAddr) -> Result<Self> {
        // Bind to wildcard address matching the external IP's address family
        let bind_addr = match external_ip {
            IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
            IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
        };
        let socket = UdpSocket::bind(bind_addr).await?;

        Ok(Self {
            socket: Arc::new(socket),
            external_ip,
            port,
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.external_ip, self.port)
    }

    /// Get a reference to the socket
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Receive a packet
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }

    /// Send a packet
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(buf, addr).await?)
    }
}
