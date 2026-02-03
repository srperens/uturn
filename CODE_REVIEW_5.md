# Code Review 5

## Findings

- **High**: Client-sent RTP/RTCP/DTLS/unknown data is relayed to other clients without verifying the
  sender has permission for the relay IP, enabling cross-client injection from any allocated client.
  `src/server.rs:221` and `src/server.rs:309`

- **High**: RTP routing can leak media between allocations when multiple clients permit the same peer
  IP; the first packet is arbitrarily assigned and SSRC is globally mapped to a single allocation,
  so collisions or shared peers can misroute indefinitely. `src/relay/engine.rs:213` and `src/lookup/
  table.rs:341`

- **Medium**: DTLS from peers is routed via handle_peer_data, which may use ChannelData if a channel is
  bound, despite the DTLS-specific path explicitly forcing Data Indication; this mismatch can break
  interoperability or confuse clients during handshake. `src/server.rs:258` and `src/relay/engine.rs:301`

- **Low**: max_requests_per_minute = 0 (unlimited) still tracks every request timestamp in the last 60s,
  allowing unbounded memory growth under abuse. `src/lookup/rate_limit.rs:41`

- **Low**: Realm from the client is accepted for MESSAGE-INTEGRITY without enforcing it matches the
  server realm; a client with the password can authenticate using any realm string, which violates
  TURN realm expectations and can complicate credential rotation. `src/turn/handler.rs:105` and `src/turn/handler.rs:360`

## Questions / assumptions

- Is single-port mode intended to require both sender and receiver to have permission for the relay
  IP? The current design enforces only the receiver side.
- Do you want to support multiple allocations permitting the same peer IP safely, or is that out of
  scope for this server?

---

## Validation Status

### 1. High: Client-sent data relay without sender permission check
**STATUS: VALID**

`relay_client_data()` only checked that the TARGET had permission for the relay IP, not the SENDER.
Any client with an allocation could inject data to other clients without CreatePermission.

**FIX**: Added sender permission check at the start of `relay_client_data()`.

### 2. High: RTP SSRC collision / shared peer IP routing
**STATUS: VALID**

SSRC was globally mapped in `by_ssrc` table. When multiple allocations permit the same peer IP
and that peer sends packets with the same SSRC, the first packet determines routing for ALL
future packets with that SSRC, causing permanent misrouting.

**FIX**: Changed `handle_rtp()` to send to ALL candidates when multiple allocations permit the
same peer IP. SSRC learning is only used when exactly one candidate exists.

### 3. Medium: DTLS routing mismatch
**STATUS: VALID**

`server.rs` called `handle_peer_data()` for DTLS which may use ChannelData, but the dedicated
`handle_dtls()` function always uses Data Indication. DTLS handshake packets should not go
via ChannelData.

**FIX**: Changed to call `handle_dtls()` instead of `handle_peer_data()` for DTLS packets.

### 4. Low: Unbounded memory when rate limit is 0
**STATUS: VALID**

Even with unlimited rate limiting, request timestamps were tracked, allowing memory growth.

**FIX**: Skip tracking `request_times` entirely when `max_requests_per_minute == 0`.

### 5. Low: Realm not enforced
**STATUS: VALID**

Client's realm was used for key computation if provided. This allows authentication with any
realm string as long as the password is correct, violating TURN realm expectations.

**FIX**: Validate that client's realm matches server's realm, and always use server's realm
for key computation. Reject requests with mismatched realm.

---

## Summary

| Issue | Severity | Status | Fix |
|-------|----------|--------|-----|
| Client data relay without sender permission | High | **VALID** | **FIXED** - Added sender permission check |
| RTP SSRC collision / shared peer routing | High | **VALID** | **FIXED** - Send to ALL candidates when ambiguous |
| DTLS routing mismatch (ChannelData vs Data Indication) | Medium | **VALID** | **FIXED** - Use handle_dtls() |
| Unbounded memory with rate limit = 0 | Low | **VALID** | **FIXED** - Skip tracking when unlimited |
| Realm not enforced | Low | **VALID** | **FIXED** - Validate realm matches server |
