# uTURN Architecture

## Overview

uTURN is a WebRTC-focused TURN server that operates on a single UDP port. Unlike traditional TURN servers that allocate separate ports for each relay, uTURN multiplexes all traffic through one port using packet-level demultiplexing.

## System Architecture

```
                                    ┌─────────────────────────────────────┐
                                    │            uTURN Server             │
                                    │                                     │
 ┌──────────┐                       │  ┌───────────────────────────────┐  │
 │  Client  │◄──────────────────────┼─►│         UDP Socket            │  │
 │    A     │    TURN control +     │  │          :3478                │  │
 └──────────┘    relayed media      │  └──────────────┬────────────────┘  │
                                    │                 │                   │
 ┌──────────┐                       │                 ▼                   │
 │  Client  │◄──────────────────────┼─►│  ┌───────────────────────────┐  │
 │    B     │                       │  │  │       Demultiplexer       │  │
 └──────────┘                       │  │  │                           │  │
                                    │  │  │  ┌─────┐ ┌─────┐ ┌─────┐  │  │
 ┌──────────┐                       │  │  │  │STUN │ │DTLS │ │ RTP │  │  │
 │  Peer    │───────────────────────┼─►│  │  └──┬──┘ └──┬──┘ └──┬──┘  │  │
 │  (media) │   media to relay      │  │  │     │       │       │     │  │
 └──────────┘                       │  │  └─────┴───────┴───────┴─────┘  │
                                    │                 │                   │
                                    │                 ▼                   │
                                    │  ┌───────────────────────────────┐  │
                                    │  │     Allocation Manager        │  │
                                    │  │                               │  │
                                    │  │  ┌─────────────────────────┐  │  │
                                    │  │  │ Allocation 1 (Client A) │  │  │
                                    │  │  │ - permissions           │  │  │
                                    │  │  │ - channels              │  │  │
                                    │  │  │ - ufrag mapping         │  │  │
                                    │  │  │ - ssrc mapping          │  │  │
                                    │  │  └─────────────────────────┘  │  │
                                    │  │  ┌─────────────────────────┐  │  │
                                    │  │  │ Allocation 2 (Client B) │  │  │
                                    │  │  │ - ...                   │  │  │
                                    │  │  └─────────────────────────┘  │  │
                                    │  └───────────────────────────────┘  │
                                    └─────────────────────────────────────┘
```

## Core Components

### 1. UDP Socket Layer

Single socket bound to the configured port (default 3478).

```rust
pub struct UdpTransport {
    socket: UdpSocket,
    external_ip: IpAddr,
    port: u16,
}
```

All packets (STUN, TURN, RTP, DTLS) arrive here and are dispatched to the demultiplexer.

### 2. Demultiplexer

Identifies packet type and routes to appropriate handler.

```rust
pub enum PacketType {
    Stun(StunMessage),
    Dtls(Vec<u8>),
    Rtp(RtpHeader, Vec<u8>),
    Rtcp(Vec<u8>),
    TurnChannelData(u16, Vec<u8>),  // channel_id, data
    Unknown,
}

impl Demuxer {
    pub fn classify(data: &[u8]) -> PacketType {
        match data.first() {
            Some(0..=3) => Self::parse_stun(data),
            Some(20..=63) => PacketType::Dtls(data.to_vec()),
            Some(64..=79) => Self::parse_channel_data(data),
            Some(128..=191) => Self::parse_rtp_rtcp(data),
            _ => PacketType::Unknown,
        }
    }
}
```

#### Protocol Detection (RFC 7983)

| First Byte | Protocol |
|------------|----------|
| 0-3 | STUN |
| 20-63 | DTLS |
| 64-79 | TURN ChannelData |
| 128-191 | RTP or RTCP |

#### STUN Session Identification

STUN messages contain USERNAME attribute: `serverUfrag:clientUfrag`

```rust
fn extract_ufrag(stun: &StunMessage) -> Option<(String, String)> {
    let username = stun.get_attribute::<Username>()?;
    let parts: Vec<&str> = username.split(':').collect();
    Some((parts[0].to_string(), parts[1].to_string()))
}
```

#### RTP/RTCP SSRC Extraction

```rust
fn extract_ssrc(rtp_data: &[u8]) -> Option<u32> {
    if rtp_data.len() < 12 {
        return None;
    }
    // SSRC is bytes 8-11 (big-endian)
    Some(u32::from_be_bytes([
        rtp_data[8], rtp_data[9], rtp_data[10], rtp_data[11]
    ]))
}
```

### 3. Allocation Manager

Tracks all active TURN allocations and their state.

```rust
pub struct AllocationManager {
    // Primary lookup: client address → allocation
    by_client: HashMap<SocketAddr, AllocationId>,

    // Reverse lookups for demuxing
    by_ufrag: HashMap<String, AllocationId>,
    by_ssrc: HashMap<u32, AllocationId>,
    by_permission: HashMap<IpAddr, Vec<AllocationId>>,

    allocations: HashMap<AllocationId, Allocation>,
}

pub struct Allocation {
    id: AllocationId,
    client_addr: SocketAddr,
    relay_addr: SocketAddr,  // Always external_ip:listen_port

    // ICE credentials
    local_ufrag: String,
    remote_ufrag: Option<String>,

    // TURN state
    permissions: HashSet<IpAddr>,
    channels: HashMap<u16, SocketAddr>,  // channel_id → peer_addr

    // Learned mappings for fast demux
    known_ssrcs: HashSet<u32>,
    known_peers: HashMap<SocketAddr, PeerState>,

    // Lifetime management
    expires_at: Instant,
    last_activity: Instant,
}
```

### 4. STUN/TURN Message Handler

Processes TURN protocol messages.

```rust
pub enum TurnRequest {
    Allocate,
    Refresh { lifetime: u32 },
    CreatePermission { peers: Vec<IpAddr> },
    ChannelBind { channel: u16, peer: SocketAddr },
    Send { peer: SocketAddr, data: Vec<u8> },
}

impl TurnHandler {
    pub async fn handle(&self,
        req: TurnRequest,
        client: SocketAddr,
        alloc_mgr: &mut AllocationManager
    ) -> TurnResponse;
}
```

### 5. Relay Engine

Forwards media between peers and clients.

```rust
impl RelayEngine {
    /// Peer → Client: Media arriving from a peer for relay to client
    pub async fn relay_to_client(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        allocation: &Allocation,
    ) {
        // Check permission
        if !allocation.permissions.contains(&peer_addr.ip()) {
            return; // Drop: no permission
        }

        // Check for channel binding (more efficient)
        if let Some(channel) = allocation.channel_for_peer(peer_addr) {
            // Send as ChannelData
            self.send_channel_data(channel, data, allocation.client_addr).await;
        } else {
            // Send as Data indication
            self.send_data_indication(peer_addr, data, allocation.client_addr).await;
        }
    }

    /// Client → Peer: Client sending via TURN to peer
    pub async fn relay_to_peer(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        allocation: &Allocation,
    ) {
        // Check permission
        if !allocation.permissions.contains(&peer_addr.ip()) {
            return;
        }

        // Send directly to peer
        self.socket.send_to(data, peer_addr).await;
    }
}
```

## Packet Flow

### Client Allocation

```
Client                              uTURN
   │                                  │
   │──── Allocate Request ───────────►│
   │                                  │ Create allocation
   │                                  │ Generate ufrag
   │◄─── Allocate Response ───────────│ (relay = external:3478)
   │     (XOR-RELAYED-ADDRESS)        │
   │                                  │
   │──── CreatePermission ───────────►│
   │     (peer IPs)                   │ Store permissions
   │◄─── Success ─────────────────────│
   │                                  │
```

### Media Relay (Peer → Client)

```
Peer                    uTURN                         Client
  │                       │                              │
  │─── RTP packet ───────►│                              │
  │    (to :3478)         │                              │
  │                       │ Demux:                       │
  │                       │ 1. First byte → RTP          │
  │                       │ 2. Extract SSRC              │
  │                       │ 3. Lookup allocation         │
  │                       │    (by SSRC or src tuple)    │
  │                       │ 4. Check permission          │
  │                       │                              │
  │                       │─── Data Indication ─────────►│
  │                       │    (or ChannelData)          │
  │                       │                              │
```

### Demux Decision Tree

```
Packet arrives from (ip, port)
           │
           ▼
    ┌──────────────┐
    │ Parse first  │
    │    byte      │
    └──────┬───────┘
           │
     ┌─────┴─────┬─────────────┬────────────┐
     ▼           ▼             ▼            ▼
   STUN       DTLS           RTP      ChannelData
     │           │             │            │
     ▼           │             ▼            ▼
 ┌────────┐      │      ┌───────────┐  ┌─────────┐
 │ Parse  │      │      │ Extract   │  │ Channel │
 │ ufrag  │      │      │   SSRC    │  │   ID    │
 └───┬────┘      │      └─────┬─────┘  └────┬────┘
     │           │            │             │
     └───────────┴────────────┴─────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Lookup by:      │
              │ 1. src (ip,port)│ ◄── fast path
              │ 2. ufrag        │
              │ 3. SSRC         │
              │ 4. channel ID   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Allocation    │
              │     found?      │
              └────────┬────────┘
                    Y/ \N
                    /   \
                   ▼     ▼
              Process   Drop
```

## State Machine

### Allocation Lifecycle

```
                    ┌──────────────┐
                    │   Initial    │
                    └──────┬───────┘
                           │ Allocate Request
                           ▼
                    ┌──────────────┐
                    │  Allocated   │◄─────────────┐
                    └──────┬───────┘              │
                           │                      │
           ┌───────────────┼───────────────┐      │
           │               │               │      │
           ▼               ▼               ▼      │
    ┌────────────┐  ┌────────────┐  ┌──────────┐  │
    │ Permission │  │  Channel   │  │ Refresh  │──┘
    │   Added    │  │   Bound    │  │          │
    └────────────┘  └────────────┘  └──────────┘
                           │
                           │ Timeout / Refresh(0)
                           ▼
                    ┌──────────────┐
                    │   Expired    │
                    └──────────────┘
```

## Module Structure

```
uturn/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point, CLI
│   ├── lib.rs               # Library root
│   ├── config.rs            # Configuration
│   ├── server.rs            # Main server loop
│   │
│   ├── transport/
│   │   ├── mod.rs
│   │   └── udp.rs           # UDP socket handling
│   │
│   ├── demux/
│   │   ├── mod.rs           # Demultiplexer
│   │   ├── protocol.rs      # Protocol detection (RFC 7983)
│   │   ├── stun.rs          # STUN parsing, ufrag extraction
│   │   └── rtp.rs           # RTP header parsing, SSRC
│   │
│   ├── turn/
│   │   ├── mod.rs
│   │   ├── message.rs       # TURN message types
│   │   ├── handler.rs       # Request/response handling
│   │   ├── allocation.rs    # Allocation state
│   │   └── auth.rs          # Long-term credentials
│   │
│   ├── relay/
│   │   ├── mod.rs
│   │   └── engine.rs        # Media relay logic
│   │
│   └── lookup/
│       ├── mod.rs
│       └── table.rs         # Fast lookup tables
│
└── tests/
    ├── integration.rs
    └── demux_tests.rs
```

## Performance Considerations

### Fast Path

For established flows, use source tuple `(ip, port)` for O(1) lookup:

```rust
// Hot path: check source tuple first
if let Some(alloc_id) = self.by_source.get(&src_addr) {
    return self.allocations.get(alloc_id);
}

// Cold path: parse packet, extract identifiers
let packet_type = Demuxer::classify(data);
// ...
```

### Memory Layout

Keep hot data together for cache efficiency:

```rust
#[repr(C)]
struct AllocationHot {
    client_addr: SocketAddr,    // 28 bytes
    expires_at: Instant,        // 16 bytes
    permissions_bitmap: u128,   // Fast permission check for common case
}
```

### Lock-Free Where Possible

Use concurrent data structures for lookup tables:

```rust
use dashmap::DashMap;

struct AllocationManager {
    by_source: DashMap<SocketAddr, AllocationId>,
    by_ufrag: DashMap<String, AllocationId>,
    // ...
}
```

## Security Considerations

1. **Authentication**: Long-term credentials (HMAC-SHA1)
2. **Permissions**: Only relay to explicitly permitted peers
3. **Rate limiting**: Per-client allocation limits
4. **Amplification**: Validate source before relaying

## Future Extensions

- **TCP TURN**: Tunnel over TCP for restrictive firewalls
- **TURNS**: TLS encryption
- **REST API**: Dynamic credential management
- **Metrics**: Prometheus endpoint
- **Clustering**: Distributed allocation state
