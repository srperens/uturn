# Code Review 3

Found issues (ordered by severity). I focused on correctness, security, and behavior regressions. No fixes applied.

## Findings

- **Critical**: Peer traffic can be misclassified as client traffic once a peer tuple is learned, which can leak media to unrelated clients. `lookup_by_source` treats `by_peer_tuple` as "client" and `handle_packet` uses that `is_client` to decide routing. After `register_peer_tuple` runs for a peer, subsequent peer packets will hit the "client" path and get relayed to all clients permitted for the relay IP, not just the intended allocation. This is a data-leak and loop risk. `src/server.rs:186-230`, `src/lookup/table.rs:284-293`, `src/lookup/table.rs:334-348`, `src/relay/engine.rs:210-232`.

- **High**: Auth is enforced only for Allocate. Refresh/CreatePermission/ChannelBind do not validate MESSAGE-INTEGRITY or NONCE even when credentials are configured. That lets any actor that can spoof the client's source tuple extend/delete allocations or add permissions without authentication. `src/turn/handler.rs:343-520`.

- **High**: RTP/RTCP demux can misclassify valid RTP as RTCP when the marker bit is set and payload type is 72-76 (raw byte 200-204). That can misroute or drop media. You're checking the raw second byte without masking. `src/demux/protocol.rs:98-123`.

- **Medium**: IPv6 paths crash or emit malformed attributes. `append_xor_*` in TURN/relay `unimplemented!` panics; in Server it emits a zero-length XOR-PEER-ADDRESS for IPv6 (invalid). Any IPv6 external IP or peer can trigger crashes or invalid responses. `src/turn/handler.rs:794-845`, `src/turn/handler.rs:979-999`, `src/relay/engine.rs:391-411`, `src/server.rs:396-418`.

- **Medium**: SSRC disambiguation for peers that share an IP is "first allocation wins," which can misroute the first packets and leak media across allocations until SSRC is learned (or permanently if SSRC collides). `src/relay/engine.rs:213-239`.

## Questions / assumptions

- Do you intend to support IPv6 at all? If not, should the server explicitly reject IPv6 at startup and for requests instead of panicking?
- Is single-port mode meant to allow multiple allocations to permit the same peer IP? If yes, you'll need deterministic routing beyond "first allocation."

## Suggested next steps

1. Decide whether to separate "client" vs "peer" detection (e.g., `is_client = by_client.contains`, and use `by_peer_tuple` only for peer routing).
2. Enforce long-term credential checks for Refresh/CreatePermission/ChannelBind (and possibly Send Indication if required by your spec stance).
3. Update RTP/RTCP demux to the RFC 7983 guidance (masking marker bit, sanity-checking RTCP header/length).

---

## Validation Status

### 1. Critical: Peer traffic misclassified as client traffic
**STATUS: VALID - Bug exists**

Analysis:
- `lookup_by_source()` in `table.rs:284-293` checks `by_peer_tuple` FIRST, then `by_client`
- `register_peer_tuple()` is called in `engine.rs:231` when learning SSRC from a peer
- In `server.rs:188`: `is_client = self.allocations.lookup_by_source(src_addr).is_some()`
- After a peer tuple is learned, `is_client` becomes true for that peer!
- Result: Peer RTP/RTCP takes the "client" path (`relay_client_data`), which broadcasts to ALL clients with permission for the relay IP, not just the intended allocation
- **This is a real data leak bug**

### 2. High: Auth only enforced for Allocate
**STATUS: VALID - Bug exists**

Analysis:
- `handle_refresh()`, `handle_create_permission()`, `handle_channel_bind()` only check `get_by_client(src_addr)`
- They call `compute_response_key()` but never VALIDATE the incoming MESSAGE-INTEGRITY
- RFC 5766 Section 10.1: "All requests after the initial Allocate must be authenticated using the same credentials"
- An attacker spoofing the client's source IP:port could:
  - Delete allocations (Refresh with lifetime=0)
  - Add arbitrary permissions (CreatePermission)
  - Bind channels to arbitrary peers (ChannelBind)
- **This is a real authentication bypass**

### 3. High: RTP/RTCP demux misclassification
**STATUS: VALID - Bug exists**

Analysis in `protocol.rs:98-123`:
```rust
let pt = data[1];  // Raw byte
if (200..=204).contains(&pt) {
    PacketType::Rtcp(data.to_vec())
```
- RTP byte 1 format: `[Marker (1 bit)][Payload Type (7 bits)]`
- If Marker=1 and PT=72-76: raw byte = 0x80 | PT = 200-204
- PT 72-76 are valid RTP payload types (reserved/dynamic range)
- **Result: Valid RTP with marker bit set and PT 72-76 is misclassified as RTCP**
- Fix: Should mask with `data[1] & 0x7F` or use additional RTCP header validation

### 4. Medium: IPv6 panics/malformed attributes
**STATUS: FIXED in previous review round**

The `unimplemented!()` panics were replaced with proper IPv6 XOR address encoding in:
- `handler.rs` (3 locations)
- `engine.rs` (1 location)
- `server.rs` (1 location)

### 5. Medium: SSRC disambiguation "first allocation wins"
**STATUS: VALID - Design limitation**

Analysis in `engine.rs:226-227`:
```rust
// If multiple allocations permit this peer, we need to disambiguate
// For now, use the first one and register the SSRC
let id = candidates[0];
```
- When multiple allocations permit the same peer IP, first RTP packet goes to arbitrary allocation
- SSRC is then "locked" to that allocation
- **Can cause media misrouting until SSRC is learned, or permanently if SSRCs collide**

---

## Summary

| Issue | Severity | Status |
|-------|----------|--------|
| Peer/client confusion data leak | Critical | **FIXED** |
| Auth bypass for Refresh/CreatePermission/ChannelBind | High | **FIXED** |
| RTP/RTCP demux marker bit bug | High | **FIXED** |
| IPv6 panics | Medium | **FIXED** |
| SSRC disambiguation | Medium | **VALID - design limitation** |

---

## Fixes Applied

### Fix 1: Peer/client confusion (Critical)

**Files changed:** `src/lookup/table.rs`, `src/server.rs`

Added separate `is_client()` method that only checks `by_client` map:
```rust
pub fn is_client(&self, addr: SocketAddr) -> bool {
    self.by_client.contains_key(&addr)
}
```

Updated `server.rs` to use `is_client()` instead of `lookup_by_source().is_some()`:
```rust
let is_client = self.allocations.is_client(src_addr);
```

This ensures learned peer tuples don't cause traffic to take the "client" path.

### Fix 2: Auth bypass (High)

**Files changed:** `src/turn/handler.rs`

Added `validate_request_auth()` helper that validates:
- MESSAGE-INTEGRITY is present (when credentials configured)
- USERNAME matches the allocation's username
- NONCE is valid and fresh
- HMAC is correct

Applied to `handle_refresh()`, `handle_create_permission()`, `handle_channel_bind()`:
```rust
let key = match self.validate_request_auth(msg, &alloc.username) {
    AuthResult::Success(k) => Some(k),
    AuthResult::NotRequired => None,
    AuthResult::Failed(response) => {
        socket.send_to(&response, src_addr).await?;
        return Ok(());
    }
};
```

### Fix 3: RTP/RTCP demux (High)

**Files changed:** `src/demux/protocol.rs`

Added `is_valid_rtcp()` validation that checks:
- Version = 2
- Length field is consistent with packet size
- Minimum size requirements for SR (28 bytes) and RR (8 bytes)

When raw byte is 200-204 (potential RTCP), validate structure before classifying:
```rust
if (200..=204).contains(&raw_pt) {
    if Self::is_valid_rtcp(data) {
        return PacketType::Rtcp(data.to_vec());
    }
    // Not valid RTCP, fall through to RTP parsing
}
```

Added tests for marker-bit edge case to prevent regression.
