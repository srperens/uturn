# uTURN

A single-port TURN relay server for WebRTC.

## Why?

Standard TURN servers require a **port range** (typically 49152-65535) for relay traffic. This is problematic for:

- Kubernetes deployments (each relay port needs service exposure)
- Restrictive firewalls (opening thousands of ports)
- Simple NAT configurations

uTURN multiplexes all traffic through a **single UDP port**. All clients share the same relay address (e.g., `server:3478`), and the server routes packets internally based on allocation lookups.

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
2. Finds other clients that have permission for the relay IP
3. Relays data to those clients via Data Indication or ChannelData

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

## Testing

Test with `turnutils_uclient` from [coturn](https://github.com/coturn/coturn):

```bash
# Basic client-to-client test
turnutils_uclient -y -u alice -w secretpass your-server-ip

# Multiple clients
turnutils_uclient -y -m 4 -u alice -w secretpass your-server-ip

# Expected output: 0% packet loss
# Total lost packets 0 (0.000000%)
```

## Features

- [x] Single UDP port operation
- [x] STUN Binding requests
- [x] TURN Allocate/Refresh
- [x] CreatePermission
- [x] ChannelBind
- [x] Send/Data Indications
- [x] Long-term credentials (RFC 5389)
- [x] Client-to-client relay (single-port mode)
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
- Peer IP permission → target allocations
- Channel number → peer address binding

## License

MIT OR Apache-2.0
