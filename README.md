# uTURN

A single-port TURN relay server for WebRTC.

## Why?

Standard TURN servers require a **port range** (typically 49152-65535) for relay traffic. This is problematic for:

- Kubernetes deployments
- Restrictive firewalls
- Simple NAT configurations

uTURN multiplexes all traffic through a **single UDP port** using packet-level demultiplexing techniques proven by [Jitsi JVB](https://github.com/jitsi/jitsi-videobridge) and [Symphony Media Bridge](https://github.com/finos/SymphonyMediaBridge).

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     Single UDP Port :3478                        │
├─────────────────────────────────────────────────────────────────┤
│  Incoming packet                                                 │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────┐                                             │
│  │ Protocol Detect │  (first byte, RFC 7983)                     │
│  │ STUN/DTLS/RTP   │                                             │
│  └────────┬────────┘                                             │
│           │                                                      │
│     ┌─────┴─────┬──────────────┐                                 │
│     ▼           ▼              ▼                                 │
│  ┌──────┐  ┌────────┐   ┌───────────┐                            │
│  │ STUN │  │  DTLS  │   │ RTP/RTCP  │                            │
│  │ ufrag│  │ connID │   │   SSRC    │                            │
│  └──┬───┘  └───┬────┘   └─────┬─────┘                            │
│     │          │              │                                  │
│     └──────────┴──────────────┘                                  │
│                │                                                 │
│                ▼                                                 │
│       ┌────────────────┐                                         │
│       │ Source Tuple   │  (ip:port → allocation)                 │
│       │    Lookup      │                                         │
│       └───────┬────────┘                                         │
│               │                                                  │
│               ▼                                                  │
│       ┌────────────────┐                                         │
│       │   Allocation   │  (relay to client)                      │
│       └────────────────┘                                         │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Run with default settings
uturn --external-ip 203.0.113.1 --port 3478

# With authentication
uturn --external-ip 203.0.113.1 --port 3478 \
      --realm example.com \
      --user alice:secretpass

# Docker
docker run -p 3478:3478/udp \
    -e EXTERNAL_IP=203.0.113.1 \
    ghcr.io/srperens/uturn
```

## Configuration

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--port` | `UTURN_PORT` | 3478 | UDP listen port |
| `--external-ip` | `UTURN_EXTERNAL_IP` | (required) | Public IP for relay addresses |
| `--realm` | `UTURN_REALM` | uturn | TURN realm |
| `--user` | `UTURN_USERS` | - | user:pass credentials |

## Features

- [x] Single UDP port operation
- [x] STUN binding requests
- [x] TURN Allocate/Refresh
- [x] CreatePermission
- [x] ChannelBind
- [x] Long-term credentials
- [ ] TCP TURN
- [ ] TURNS (TLS)
- [ ] REST API for dynamic credentials

## How Demultiplexing Works

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

**TL;DR:** We use the same techniques as Jitsi/SMB:

1. **Protocol detection** (RFC 7983) - first byte identifies STUN/DTLS/RTP
2. **ICE username fragment** - STUN messages contain session identifier
3. **SSRC** - RTP header contains stream identifier (unencrypted in SRTP)
4. **Source tuple** - (ip, port) uniquely identifies peer after handshake

## License

MIT OR Apache-2.0
