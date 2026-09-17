# uTURN

A single-port TURN relay for WebRTC. Both internal (client-to-client) and
external (client-to-peer) traffic is routed over one UDP port — so there is a
single port to expose, not a relay port range.

> **Scope: this is a WebRTC relay, not a general-purpose TURN server.**
>
> Because every client shares one relay address, client-to-client traffic
> cannot be resolved from the destination address alone. uTURN routes it by the
> **ICE ufrag** carried in the STUN USERNAME, which means both sides must be ICE
> agents — in practice, WebRTC endpoints. Plain client-to-external-peer
> relaying follows RFC 5766 and works with any TURN client.
>
> The shared relay address is a deliberate deviation from the spec, not a
> missing feature: RFC 5766 Section 5 requires that "[b]oth the relayed
> transport address and the 5-tuple MUST be unique across all allocations"
> (RFC 8656 Section 6 keeps the requirement). uTURN keeps the 5-tuple unique
> and gives up the other half, which is exactly why client-to-client pairing
> has to be inferred from ICE ufrags. There is also no TCP transport and no
> TURNS (TLS/DTLS). If you need a standards-complete TURN deployment, use
> coturn.

## Why?

Standard TURN servers require a **port range** (typically 49152-65535) for relay traffic. This is problematic for:

- Kubernetes deployments (each relay port needs service exposure)
- Restrictive firewalls (opening thousands of ports)
- Simple NAT configurations

uTURN multiplexes all traffic through a **single UDP port**. All clients share the same relay address (e.g., `server:3478`), and the server routes packets internally based on allocation lookups.

### Compared to STUNner

[STUNner](https://github.com/l7mp/stunner) solves the same Kubernetes problem from the other end: it terminates TURN at the cluster edge and hands media to workloads over pod networking, so the media path depends on the cluster's networking rather than on one port.

uTURN keeps everything on the one UDP port it listens on. Client-to-client traffic is relayed inside the server and never leaves that port, and external peers are reached from it too, so there is one port to expose per instance. The trade-off is scope: uTURN is a relay for WebRTC media, not a Kubernetes gateway — there is no CRD, no control plane and no cluster integration.

**One instance per relay address.** All allocation state is in-process, so every participant of a call must reach the *same* uTURN process. A Service with several replicas does not work: kube-proxy ["select[s] a backend Pod at random"](https://kubernetes.io/docs/reference/networking/virtual-ips/) by default, so a client's packets can land on a pod that has no allocation for it. `sessionAffinity: ClientIP` — which is what STUNner sets on the Services exposing its Gateways — fixes that much, but not client-to-client: two clients have two source IPs and can still be pinned to two different pods, and neither can then see the other's ufrag. Run one replica per Service and scale out by adding instances, steering all participants of a call to the same one. STUNner does not have this constraint, because its dataplane pods relay to a backend that any of them can reach over pod networking.

## How Single-Port TURN Works

```
Standard TURN:                    Single-Port TURN (uTURN):
┌─────────────────────┐           ┌─────────────────────┐
│   TURN Server       │           │   TURN Server       │
│                     │           │                     │
│  Client A ←→ :49152 │           │  Client A ──┐       │
│  Client B ←→ :49153 │           │             ├→ :3478│
│  Client C ←→ :49154 │           │  Client B ──┤       │
│         ...         │           │             │       │
│  (thousands of      │           │  Client C ──┘       │
│   relay ports)      │           │  (single port)      │
└─────────────────────┘           └─────────────────────┘
```

When Client A sends data to the relay address, uTURN:
1. Identifies the sender by source address
2. Routes to the correct peer via ICE ufrag matching (bi-directional pairing)
3. Delivers via Data Indication or ChannelData

## Quick Start

```bash
# Build
cargo build --release

# Run with authentication
./target/release/uturn \
    --external-ip 203.0.113.1 \
    --port 3478 \
    --user alice:secretpass

# Docker
docker run -p 3478:3478/udp \
    -e UTURN_EXTERNAL_IP=203.0.113.1 \
    -e UTURN_USERS=alice:secretpass \
    ghcr.io/srperens/uturn
```

## Configuration

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--port` | `UTURN_PORT` | 3478 | UDP listen port |
| `--external-ip` | `UTURN_EXTERNAL_IP` | (required) | Public IP for relay addresses |
| `--realm` | `UTURN_REALM` | uturn | TURN realm for authentication |
| `--user` | `UTURN_USERS` | - | Credentials in `user:pass` format (repeatable) |
| `--log-level` | `UTURN_LOG_LEVEL` | info | Log level: trace, debug, info, warn, error |
| `--max-allocations-per-ip` | `UTURN_MAX_ALLOC_PER_IP` | 200 | Max concurrent allocations per IP (0 = unlimited) |
| `--rate-limit-per-minute` | `UTURN_RATE_LIMIT` | 30 | Max allocation requests per IP per minute (0 = unlimited) |
| `--nonce-lifetime-secs` | `UTURN_NONCE_LIFETIME` | 3600 | Nonce validity period in seconds |

## Testing

Test with `turnutils_uclient` and `turnutils_peer` from [coturn](https://github.com/coturn/coturn). This exercises the client-to-external-peer path (RFC 5766), not the ufrag-routed client-to-client path — that one needs real ICE agents:

```bash
# Start a peer server on the TURN server (or any reachable host)
ssh your-server 'turnutils_peer -p 33333 &'

# Run the TURN client test
turnutils_uclient -u alice -w secretpass -e your-server-ip -r 33333 your-server-ip

# Expected output: 0% packet loss
# Total lost packets 0 (0.000000%)

# Clean up
ssh your-server 'pkill turnutils_peer'
```

Note: The `-y` self-test flag doesn't work with single-port TURN since client and peer share the same relay address.

## Features

- [x] Single UDP port operation
- [x] STUN Binding requests
- [x] TURN Allocate/Refresh
- [x] CreatePermission
- [x] ChannelBind
- [x] Send/Data Indications
- [x] Long-term credentials (RFC 5389)
- [x] Client-to-client relay (single-port mode, ICE ufrag routed)
- [ ] TCP TURN
- [ ] TURNS (TLS/DTLS)
- [ ] REST API for ephemeral credentials

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details.

**Packet demultiplexing** (RFC 7983):
- First byte 0-3: STUN messages
- First byte 20-63: DTLS
- First byte 64-127: TURN ChannelData
- First byte 128-191: RTP/RTCP

**Allocation lookup:**
- Source address → client allocation
- ICE ufrag pairing → bi-directional peer matching (prevents bandwidth multiplication)
- Peer IP permission → target allocations (fallback)
- Channel number → peer address binding

## License

MIT OR Apache-2.0
