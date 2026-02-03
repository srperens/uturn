# uTURN: Single-Port TURN Relay

Research notes for a potential single-port TURN server implementation.

## The Problem

Standard TURN servers (coturn, turn-rs) require a **port range** (typically 49152-65535) for relay traffic:

- Client connects to TURN on port 3478
- TURN allocates a relay address like `external_ip:50000`
- Peer sends media to that relay port
- TURN forwards to client

This means exposing thousands of UDP ports, which is problematic for:
- Kubernetes deployments (port range exposure is messy)
- Restrictive firewalls
- Simple NAT configurations (only one port forward needed)

## Why Can't Everything Use One Port?

The traditional answer: **the destination port IS the demultiplexer**.

```
Peer A sends to :50000 → TURN knows it's for Client B
Peer X sends to :50001 → TURN knows it's for Client C
```

If everything arrives on :3478, how does TURN know which allocation to route to?

## The Solution: Packet-Level Demultiplexing

**It turns out there's enough information in the packets themselves.**

### Existing Implementations

Both **Jitsi JVB** and **Symphony Media Bridge** run on a single UDP port using these techniques:

| Product | Single Port | Config |
|---------|-------------|--------|
| [Jitsi JVB](https://github.com/jitsi/jitsi-videobridge) | UDP 10000 | Default |
| [Symphony Media Bridge](https://github.com/finos/SymphonyMediaBridge) | UDP 10000 | `ice.singlePort: 10000` |

### How They Demultiplex

#### 1. Protocol Detection (RFC 7983)

First byte of packet determines protocol type:

```
Byte Value    Protocol
─────────────────────────
0-3           STUN
20-63         DTLS
64-79         TURN ChannelData
128-191       RTP/RTCP
```

#### 2. STUN Messages: ICE Username Fragment (ufrag)

STUN binding requests contain a `USERNAME` attribute with format `serverUfrag:clientUfrag`:

```
STUN packet arrives
├── Parse USERNAME attribute
├── Extract ufrag pair
├── Lookup session by ufrag
└── Route to that session
```

#### 3. RTP/RTCP: SSRC Identifier

RTP header contains 32-bit SSRC (not encrypted, even in SRTP):

```
RTP packet arrives
├── Bytes 0-1: Version, flags, payload type
├── Bytes 2-3: Sequence number
├── Bytes 4-7: Timestamp
├── Bytes 8-11: SSRC ← use this!
└── Lookup which session owns SSRC
```

#### 4. Source Address Tuple

`(source_ip, source_port)` uniquely identifies a connection once established:

- Each PeerConnection uses different local ports
- TURN permissions already track allowed peer addresses
- Can use as fast-path lookup after initial STUN exchange

## Applying This to TURN

A single-port TURN server could work like this:

### Allocation Phase

```
Client B → TURN:3478  Allocate Request
TURN → Client B       Allocate Response (relay = external_ip:3478)
                      Note: Same port! Internally track allocation ID

Client B → TURN:3478  CreatePermission(Peer A's IP)
TURN                  Records: Peer A → Client B's allocation
```

### Media Relay Phase

```
Peer A (192.168.1.100:54321) → TURN:3478  [RTP packet, SSRC=0xABCD]

TURN demux logic:
├── First byte = 128-191 → It's RTP
├── Check (src_ip=192.168.1.100, src_port=54321)
│   └── Matches permission for Client B's allocation
├── OR check SSRC 0xABCD
│   └── Registered to Client B's session
└── Forward to Client B via their TURN connection
```

### Edge Cases to Handle

| Scenario | Solution |
|----------|----------|
| Same peer, multiple allocations | Different local ports per PeerConnection |
| SSRC collision | Fall back to source tuple lookup |
| Non-RTP traffic (DTLS) | Use source tuple + connection state |
| TURN ChannelData | Already has channel number for demux |

## Implementation Considerations

### Advantages

- Single port exposure (firewall-friendly)
- Kubernetes-native (no port range)
- Simpler NAT configuration

### Challenges

- Protocol-aware (must parse RTP headers) - breaks TURN's "relay any UDP" design
- State tracking is more complex
- Need to handle SSRC changes gracefully
- Performance: header parsing vs port-based routing

### Existing Building Blocks

- **[pion/turn](https://github.com/pion/turn)** - Go TURN library, could be extended
- **[webrtc-rs](https://github.com/webrtc-rs/webrtc)** - Rust WebRTC stack with TURN
- **RFC 7983** - Multiplexing scheme for DTLS/SRTP/STUN

## Prior Art & References

### Standards

- [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) - TURN protocol (current)
- [RFC 7983](https://www.rfc-editor.org/rfc/rfc7983.html) - DTLS/SRTP/STUN multiplexing
- [RFC 5761](https://www.rfc-editor.org/rfc/rfc5761.html) - RTP/RTCP mux on single port
- [draft-peterson-rosenberg-avt-rtp-ssrc-demux](https://datatracker.ietf.org/doc/html/draft-peterson-rosenberg-avt-rtp-ssrc-demux-00) - SSRC demux proposal (2004, expired but noted "TURN servers could readily be adapted")

### Implementations

- [Jitsi JVB](https://github.com/jitsi/jitsi-videobridge) - Single-port SFU
- [Symphony Media Bridge](https://github.com/finos/SymphonyMediaBridge) - Single-port SFU (`ice.singlePort`)
- [STUNner](https://github.com/l7mp/stunner) - K8s TURN (uses pod networking, not true single-port)
- [mediasoup discussion](https://mediasoup.discourse.group/t/use-only-a-single-udp-port-instead-a-big-port-range-for-media-connection/3328) - Uses STUN ufrag for demux

### Why No One Has Built This

1. TURN is designed to be protocol-agnostic (relay arbitrary UDP)
2. SFUs solve the same problem differently (they're the endpoint, not a relay)
3. Complexity vs just opening ports
4. TCP TURN on 443 is "good enough" for firewall traversal

## Project Idea: uTURN

A minimal single-port TURN server in Rust.

### Design Goals

- Single UDP port for all traffic
- WebRTC-focused (OK to be RTP-aware)
- Simple configuration
- Kubernetes-friendly
- High performance (Rust + zero-copy where possible)

### MVP Scope

1. STUN binding responses
2. TURN Allocate/Refresh/CreatePermission
3. Single-port relay using:
   - Source tuple for established flows
   - SSRC lookup as fallback
4. Long-term credentials auth
5. Docker image

### Non-Goals (initially)

- TCP TURN
- TURNS (TLS)
- Full RFC compliance for edge cases
- Non-WebRTC UDP relay

---

*Notes compiled 2026-02-03*
