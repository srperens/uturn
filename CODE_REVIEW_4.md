# Code Review 4

## Findings

- **Critical**: Cross-client data leak when multiple allocations permit the same peer IP. `handle_rtcp` and `handle_dtls` pick `candidates[0]` and forward to that client, so traffic from a shared peer IP can be delivered to the wrong allocation. `handle_rtp` has the same problem in the "fall back to permission-based lookup" path and then permanently binds the SSRC to the first allocation. `src/relay/engine.rs:213`, `src/relay/engine.rs:265`, `src/relay/engine.rs:296`.

- **High**: Send Indication internal routing bypasses the sender's permission check. When `peer_addr == our_addr`, the function relays data without verifying that the sender permitted the relay IP. This lets a client send to others without CreatePermission. `src/turn/handler.rs:675`.

- **High**: IPv6 XOR address encoding is incorrect (missing transaction ID XOR). IPv6 addresses in XOR-MAPPED-ADDRESS, XOR-RELAYED-ADDRESS, and XOR-PEER-ADDRESS are encoded using only the magic cookie and then raw bytes, which breaks IPv6 interop and can misroute traffic. Affected paths include building STUN responses and Data Indications. `src/turn/handler.rs:911`, `src/turn/handler.rs:957`, `src/turn/handler.rs:1130`, `src/server.rs:399`, `src/relay/engine.rs:392`.

- **Medium**: STUN error responses are padded incorrectly. The padding loop uses `20 + padded_len` (value-only) instead of `20 + 4 + padded_len` (attribute header + value), so many error responses have invalid length (not 4-byte aligned) and can be rejected by clients. `src/turn/handler.rs:875`, `src/turn/handler.rs:1005`.

- **Medium**: IPv6 external IP is accepted but the server binds only to IPv4 (`0.0.0.0`), so the relay address can be unreachable or misleading for IPv6 clients. `src/server.rs:35`, `src/transport/udp.rs:20`.

## Open questions / assumptions

- Is single-port mode expected to support multiple clients permitting the same peer IP at once? If yes, the "pick first candidate" routing is a correctness/security bug; if no, you may want to enforce that invariant explicitly.
- Is IPv6 in scope? If it's out of scope, consider explicitly rejecting IPv6 external IPs and peer addresses to avoid silent misrouting.

---

## Validation Status

### 1. Critical: Cross-client data leak with shared peer IP
**STATUS: VALID**

`handle_rtcp()` (line 275) and `handle_dtls()` (line 305) just pick `candidates[0]` without any disambiguation. If multiple allocations permit the same peer IP, traffic goes to the wrong client.

### 2. High: Send Indication bypasses sender permission check
**STATUS: VALID**

In `handle_send()` when `peer_addr == our_addr` (lines 677-715), it relays to all allocations that have permission for the relay IP. But it never checks if the SENDER has permission to send to the relay address. A client could send data without calling CreatePermission first.

### 3. High: IPv6 XOR encoding incorrect
**STATUS: VALID**

Looking at lines 942-952, the code only XORs the first 4 bytes with the magic cookie and leaves the remaining 12 bytes unXORed. Per RFC 5389, IPv6 addresses must be XORed with magic cookie (4 bytes) + transaction ID (12 bytes). Current code is wrong.

### 4. Medium: STUN error response padding
**STATUS: VALID**

Line 901: `while response.len() < 20 + padded_len`

This should be `20 + 4 + padded_len` to account for the 4-byte attribute header. Current code under-pads when reason string length is not 4-byte aligned.

### 5. Medium: IPv6 external IP with IPv4-only bind
**STATUS: VALID**

Line 41: `SocketAddr::from(([0, 0, 0, 0], config.port))` - binds to IPv4 only. If external_ip is IPv6, the relay address is unreachable.

---

## Summary

| Issue | Severity | Status | Fix |
|-------|----------|--------|-----|
| Cross-client data leak (candidates[0]) | Critical | **VALID** | **FIXED** - handle_rtcp/handle_dtls now send to ALL allocations |
| Send Indication permission bypass | High | **VALID** | **FIXED** - Added sender permission check at line 684 |
| IPv6 XOR encoding wrong | High | **VALID** | **FIXED** - All append_xor_* functions now XOR with transaction_id |
| STUN error padding wrong | Medium | **VALID** | **FIXED** - Changed to `20 + 4 + padded_len` |
| IPv6 external IP with IPv4 bind | Medium | **VALID** | **FIXED** - Bind address now matches external_ip family |
