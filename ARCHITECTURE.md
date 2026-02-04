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
                                    │  │  │ - ice_ufrag             │  │  │
                                    │  │  │ - ice_remote_ufrag      │  │  │
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

#### STUN Session Identification (ICE Ufrag Pairing)

STUN Binding Requests contain USERNAME attribute: `remoteUfrag:localUfrag`

Each allocation learns its ICE credentials from STUN messages and uses **bi-directional matching** to find its peer:

```rust
// Extract ufrags from STUN USERNAME attribute
fn extract_stun_ufrags(data: &[u8]) -> Option<(String, String)> {
    // Parse USERNAME attribute (type 0x0006)
    // Format: "remoteUfrag:localUfrag"
    // Returns (remote_ufrag, local_ufrag)
}

// Bi-directional matching: find allocations where their
// (local, remote) matches our (remote, local)
fn find_ice_peers(sender_local: &str, sender_remote: &str) -> Vec<AllocationId> {
    // If sender has local=X, remote=Y
    // Find peers with local=Y, remote=X
}
```

The ICE ufrag pairing is learned atomically on the first STUN Binding Request using DashMap's entry API, preventing duplicate registrations when the same STUN message is broadcast to multiple allocations.

### 3. Allocation Manager

Tracks all active TURN allocations and their state.

```rust
pub struct AllocationTable {
    // Primary lookup: client address → allocation
    by_client: DashMap<SocketAddr, AllocationId>,

    // Reverse lookups for demuxing
    by_ufrag: DashMap<String, AllocationId>,         // TURN ufrag
    by_ice_ufrag: DashMap<String, AllocationId>,     // ICE local ufrag
    by_peer_ip: DashMap<IpAddr, Vec<AllocationId>>,  // Permission-based
    by_peer_tuple: DashMap<SocketAddr, AllocationId>, // Direct peer lookup

    allocations: DashMap<AllocationId, Allocation>,
}

pub struct Allocation {
    id: AllocationId,
    client_addr: SocketAddr,
    relay_addr: SocketAddr,  // Always external_ip:listen_port

    // TURN credentials
    ufrag: String,

    // ICE credentials (learned from STUN Binding Requests)
    ice_ufrag: RwLock<Option<String>>,         // This allocation's ICE ufrag
    ice_remote_ufrag: RwLock<Option<String>>,  // Remote peer's ICE ufrag

    // TURN state
    permissions: RwLock<HashSet<IpAddr>>,
    channels: DashMap<u16, SocketAddr>,  // channel_id → peer_addr

    // Lifetime management
    expires_at: RwLock<Instant>,
    last_activity: AtomicU64,
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

Forwards media between peers and clients, with ICE ufrag-based routing.

```rust
impl RelayEngine {
    /// Handle ChannelData from client - may contain STUN for ICE pairing
    pub async fn handle_channel_data(&self, data: &[u8], alloc: &Allocation) {
        // If this is a STUN Binding Request, learn ICE credentials
        if let Some((remote_ufrag, local_ufrag)) = extract_stun_ufrags(data) {
            // Atomically register this allocation's ICE ufrags
            self.allocations.register_ice_ufrags(alloc.id, local_ufrag, remote_ufrag);

            // Find peer allocations using bi-directional matching
            let ice_peers = self.allocations.find_ice_peers(&local, &remote);
            // Route to matched peers...
        }
    }

    /// Peer → Client: Media arriving from a peer for relay to client
    pub async fn relay_to_client(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        allocation: &Allocation,
    ) {
        // Check permission
        if !allocation.has_permission(&peer_addr.ip()) {
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
        if !allocation.has_permission(&peer_addr.ip()) {
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
  │                       │ 2. Lookup by peer tuple      │
  │                       │ 3. Or lookup by ICE pairing  │
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
     ▼           │             │            ▼
 ┌────────┐      │             │       ┌─────────┐
 │ Parse  │      │             │       │ Channel │
 │ ufrag  │      │             │       │   ID    │
 └───┬────┘      │             │       └────┬────┘
     │           │             │            │
     ▼           │             │            │
 ┌────────────┐  │             │            │
 │ Learn ICE  │  │             │            │
 │ pair for   │  │             │            │
 │ allocation │  │             │            │
 └───┬────────┘  │             │            │
     │           │             │            │
     └───────────┴─────────────┴────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Lookup by:      │
              │ 1. src (ip,port)│ ◄── fast path
              │ 2. ICE ufrag    │ ◄── bi-directional
              │    pairing      │     matching
              │ 3. channel ID   │
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

## Single-Port Routing with ICE Ufrag Pairing

### The Problem

In single-port TURN, all clients share the same relay address (`external_ip:port`). When a peer sends media to this address, we must determine which client should receive it.

**Without proper routing:** If multiple clients have `CreatePermission` for the same peer IP, data gets duplicated to all of them, causing bandwidth multiplication.

### The Solution: ICE Ufrag Bi-Directional Matching

WebRTC ICE connectivity checks use STUN Binding Requests with a USERNAME attribute formatted as `remoteUfrag:localUfrag`. Each side of a connection uses complementary credentials:

```
Client A (sender):   local=X, remote=Y  →  USERNAME="Y:X"
Client B (receiver): local=Y, remote=X  →  USERNAME="X:Y"
```

When Client A sends a STUN Binding Request, we:
1. Extract `(remote_ufrag=Y, local_ufrag=X)` from USERNAME
2. Register `ice_ufrag=X` and `ice_remote_ufrag=Y` on Client A's allocation
3. Look for allocations where `ice_ufrag=Y` and `ice_remote_ufrag=X` (the inverse)
4. Found match = Client B is Client A's peer

### Atomic Registration

Since STUN Binding Requests may be broadcast to multiple allocations (via IP-based permission lookup), we use atomic registration with DashMap's entry API:

```rust
match self.by_ice_ufrag.entry(local_ufrag) {
    Entry::Occupied(_) => false,  // Already claimed by another allocation
    Entry::Vacant(entry) => {
        // First one wins - register atomically
        entry.insert(id);
        true
    }
}
```

This ensures each ICE ufrag is registered exactly once, preventing duplicate routing.

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
│   │   └── protocol.rs      # Protocol detection (RFC 7983)
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
│       ├── table.rs         # Allocation table & ICE ufrag indexes
│       └── rate_limit.rs    # Per-client rate limiting
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
