# Relay interop harness

A runnable end-to-end check of uTURN's single-port client-to-client relaying,
using two real headless-Chromium peers.

It exists to guard the routing logic in `handle_binding_request` /
`handle_send` (see PR #12): that path is interop-sensitive, and the in-crate
unit tests only cover the server logic in isolation.

`relaytest.js` defaults to relay address `192.0.2.2:3478` (a documentation
address, TEST-NET-1) and credentials `test:testpass`. Override with env vars.

## Prerequisites

- A running uTURN with a known credential, reachable on a **non-loopback** IP
  (the server refuses loopback as a peer, so the relay address can't be
  `127.0.0.1`).
- Node with `playwright` available.

```sh
cargo run -- --external-ip 192.0.2.2 --port 3478 --user test:testpass
```

## Run

```sh
# CHROMIUM_PATH is optional; omit it to use Playwright's bundled Chromium.
TURN_URL='turn:192.0.2.2:3478?transport=udp' node relaytest.js
ICE_RESTART=1 node relaytest.js        # also exercises an ICE restart mid-call
```

Two peers with `iceTransportPolicy: 'relay'` connect through the server and
exchange DataChannel bytes. Exit 0 with a `roundtrip: pong:ping` line means a
full relayed call works (ICE **and** DTLS completed).

Expected: exactly one packet hits the "drop, no ufrag match yet" path on the
first connectivity check (the peer hasn't registered yet); STUN retransmits and
the call converges. That drop is by design, not a failure.

## Scope / caveats

- Both browser peers run in one Chromium instance on one host, over loss-free
  loopback-class networking. This checks that a relayed call works end to end;
  it is not a NAT or adversarial-network test.
