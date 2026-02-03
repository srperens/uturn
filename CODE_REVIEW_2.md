# Code Review 2 - uTURN TURN Server

**Date:** 2026-02-03
**Evaluated:** 2026-02-03
**Fixed:** 2026-02-03

## Findings Evaluation Summary

| # | Finding | Claimed Severity | Verdict | Status |
|---|---------|------------------|---------|--------|
| 1 | MESSAGE-INTEGRITY non-compliant | Critical | ❌ **INCORRECT** | N/A |
| 2 | RTP broadcast (no SSRC routing) | High | ✅ Confirmed | ✅ **FIXED** |
| 3 | RTCP classification broken | High | ✅ Confirmed | ✅ **FIXED** |
| 4 | Quota not decremented on cleanup | Medium | ✅ Confirmed | ✅ **FIXED** |
| 5 | Stale peer-tuple mappings | Medium | ✅ Confirmed | ✅ **FIXED** |
| 6 | Nonce predictable | Medium | ✅ Confirmed | ✅ **FIXED** |
| 7 | RateLimiter::cleanup() never called | Secondary | ✅ Confirmed | ✅ **FIXED** |
| 8 | REQUESTED-TRANSPORT not validated | Secondary | ✅ Confirmed | ✅ **FIXED** |

---

## Detailed Evaluation

### 1. ❌ MESSAGE-INTEGRITY - INCORRECT FINDING

**Claimed:** MESSAGE-INTEGRITY generation and verification exclude the MESSAGE-INTEGRITY attribute header/value, which is non-compliant.

**Evaluation:** The implementation is **correct per RFC 5389**.

RFC 5389 Section 15.4 specifies:
> "The text used as input to HMAC is the STUN message, including the header, up to and including the attribute preceding the MESSAGE-INTEGRITY attribute."

And:
> "The Length field of the STUN message header is modified to point to the end of the MESSAGE-INTEGRITY attribute."

The code correctly:
- Hashes everything BEFORE MESSAGE-INTEGRITY (not including it)
- Adjusts the length field to include MESSAGE-INTEGRITY (24 bytes)

**Verification code (handler.rs:248-258):**
```rust
let mut msg_for_hmac = msg.raw[..offset].to_vec();  // Up to MESSAGE-INTEGRITY
let new_len = (offset - 20 + 24) as u16;             // Adjust length to include it
msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());
```

**Generation code (handler.rs:907-913):**
```rust
let new_len = (buf.len() - 20 + 24) as u16;          // Length includes MESSAGE-INTEGRITY
buf[2..4].copy_from_slice(&new_len.to_be_bytes());
let integrity = TurnAuth::compute_message_integrity(buf, key);  // Hash before appending
```

This follows the RFC exactly. **No fix needed.**

---

### 2. ✅ RTP Broadcast (No SSRC Routing) - CONFIRMED

**Issue:** RTP from peers is never routed through the SSRC-aware path, so the server broadcasts to all allocations that permit a peer IP.

**Evaluation:** Confirmed. In `server.rs:199-203`:
```rust
} else {
    let candidates = self.allocations.lookup_by_peer_ip(src_addr.ip());
    if !candidates.is_empty() {
        self.relay_engine.handle_peer_data(&data, src_addr).await?;  // Broadcasts to ALL
```

The SSRC-aware `handle_rtp()` function exists in `relay/engine.rs:213` but is never called from `server.rs`. Instead, `handle_peer_data()` broadcasts to all allocations permitting the peer IP.

**Impact:** Media leakage when multiple clients permit the same peer IP.

**Files:** `src/server.rs:199`, `src/relay/engine.rs:40`

---

### 3. ✅ RTCP Classification Broken - CONFIRMED

**Issue:** Masking the PT byte with 0x7F makes values 200-204 unreachable.

**Evaluation:** Confirmed. In `protocol.rs:111-113`:
```rust
let pt = data[1] & 0x7F;
if (200..=204).contains(&pt) {
```

RTCP payload types are 200-204 (0xC8-0xCC in hex). When masked:
- SR (200 = 0xC8): `0xC8 & 0x7F = 72` - NOT in 200-204
- RR (201 = 0xC9): `0xC9 & 0x7F = 73` - NOT in 200-204
- etc.

RTCP will **never** be correctly classified - always misrouted as RTP with incorrect SSRC parsing.

**Fix:** Check `data[1]` directly without masking, or use range 72-76 after masking.

**File:** `src/demux/protocol.rs:111`

---

### 4. ✅ Quota Not Decremented on Cleanup - CONFIRMED

**Issue:** Allocation quota accounting is not updated when allocations expire/are cleaned up.

**Evaluation:** Confirmed. The cleanup task in `server.rs:95-114` calls:
- `cleanup_allocations.cleanup_expired()`
- `cleanup_allocations.cleanup_inactive()`
- `cleanup_allocations.cleanup_orphaned_senders()`

None of these call `rate_limiter.record_deallocation()`. Only explicit deletion via Refresh(lifetime=0) at `handler.rs:350` updates the quota.

**Impact:** After allocations expire, the per-IP quota counter remains inflated, potentially blocking future allocations permanently.

**Files:** `src/server.rs:95`, `src/lookup/table.rs:361`

---

### 5. ✅ Stale Peer-Tuple Mappings - CONFIRMED

**Issue:** `by_peer_tuple` entries are inserted but never recorded in `known_peers`, so they're never removed on cleanup.

**Evaluation:** Confirmed. In `table.rs:334-337`:
```rust
pub fn register_peer_tuple(&self, id: AllocationId, peer_addr: SocketAddr) {
    self.by_peer_tuple.insert(peer_addr, id);  // Inserted but not tracked
}
```

Cleanup only removes entries found in `known_peers` (table.rs:377-379):
```rust
for entry in alloc.known_peers.iter() {
    self.by_peer_tuple.remove(entry.key());
}
```

Since `register_peer_tuple` doesn't add to `known_peers`, these entries are never cleaned up.

**Impact:** Stale mappings can cause `lookup_by_source` to return wrong allocations.

**File:** `src/lookup/table.rs:334`

---

### 6. ✅ Nonce Predictable - CONFIRMED

**Issue:** Nonce generation is timestamp-only and not bound to a server secret.

**Evaluation:** Confirmed. In `auth.rs:45-52`:
```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
format!("{:016x}", timestamp)
```

Pure timestamp with no server secret. Anyone knowing the approximate server time can predict valid nonces.

**Impact:** Lower security, though MESSAGE-INTEGRITY still requires the correct password. A proper nonce should include HMAC(timestamp, server_secret).

**File:** `src/turn/auth.rs:45`

---

## Secondary Notes - CONFIRMED

### RateLimiter::cleanup() Never Called ✅

The `RateLimiter::cleanup()` method exists at `rate_limit.rs:91` but is never scheduled. The rate-limit map can grow unbounded with many source IPs over time.

**File:** `src/lookup/rate_limit.rs:91`

### REQUESTED-TRANSPORT Not Validated ✅

Allocate requests don't validate the `REQUESTED-TRANSPORT` attribute. Per RFC 5766, this should be checked (must be UDP, value 17).

**File:** `src/turn/handler.rs` (handle_allocate)

---

## Open Questions / Assumptions

- Are you expecting multiple allocations to permit the same peer IP? If yes, the RTP/SSRC disambiguation path should be used; otherwise media privacy risks are higher.

- Is long-term credential auth expected in production? ~~If yes, the MESSAGE-INTEGRITY behavior is likely blocking real clients and needs correction.~~ **Evaluated: MESSAGE-INTEGRITY implementation is correct.**

---

## Fixed Issues

All confirmed issues have been resolved:

| Priority | Issue | Fix Applied |
|----------|-------|-------------|
| **High** | RTCP classification | ✅ Check `data[1]` directly without 0x7F mask (`protocol.rs:111`) |
| **High** | RTP broadcast | ✅ Route peer RTP through `handle_rtp()` for SSRC disambiguation (`server.rs:199`) |
| **Medium** | Quota not decremented | ✅ Cleanup functions return removed IPs, server calls `record_deallocation()` (`table.rs`, `server.rs`) |
| **Medium** | Stale peer-tuple | ✅ `register_peer_tuple()` now adds to `known_peers` (`table.rs:336`) |
| **Medium** | Nonce predictable | ✅ Nonce now uses `timestamp:HMAC(timestamp,secret)` format (`auth.rs:45`, `config.rs`) |
| **Low** | RateLimiter cleanup | ✅ Added `cleanup_rate_limiter.cleanup()` call in cleanup task (`server.rs:135`) |
| **Low** | REQUESTED-TRANSPORT | ✅ Validate attribute in Allocate handler, reject non-UDP (`handler.rs:197`)
