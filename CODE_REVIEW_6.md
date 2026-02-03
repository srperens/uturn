# Code Review 6

## Findings

- **High**: 438 Stale Nonce responses are built with build_error_response, which omits REALM/NONCE, so
  clients can't recover from stale nonces during Allocate/Refresh/CreatePermission/ChannelBind. This
  will cause auth loops and failed re-auth. (`src/turn/handler.rs:90-99`, `src/turn/handler.rs:351-362`)

- **Medium**: Send Indications routed to the relay address return early without alloc.touch_received(),
  so an actively sending client can be evicted as "inactive". (`src/turn/handler.rs:701-758`)

- **Medium**: Allocation creation is not atomic (check-then-create across tasks). Concurrent Allocate
  requests from the same client can create multiple allocations, inflate per-IP quota counts, and
  leave orphaned allocations until cleanup. (`src/turn/handler.rs:262-283`, `src/lookup/table.rs:249-265`)

## Open questions / assumptions

- Are you okay with 438 responses including REALM/NONCE (and MESSAGE-INTEGRITY when applicable), per
  RFC expectations, or do you intentionally keep error responses minimal?

---

## Validation Status

### 1. High: 438 Stale Nonce responses missing REALM/NONCE
**STATUS: VALID**

`build_error_response()` was used for 438 Stale Nonce, which only includes ERROR-CODE attribute.
Per RFC 5389, 438 responses MUST include REALM and a fresh NONCE so clients can retry authentication.
Without these, clients enter an auth loop and cannot recover.

**FIX**: Created new `build_stale_nonce_response()` function that includes ERROR-CODE (438),
REALM, and a fresh NONCE. Updated both call sites (validate_request_auth and handle_allocate_request).

### 2. Medium: Send Indication to relay doesn't touch allocation
**STATUS: VALID**

When handling Send Indication to the relay address, the early return path at line 758 didn't call
`alloc.touch_received()`. This means clients actively sending data via Send Indication could be
evicted as "inactive" by the allocation cleanup process.

**FIX**: Added `alloc.touch_received()` before the early return in the relay address handling path.

### 3. Medium: Allocation creation not atomic
**STATUS: VALID**

There was a race condition between `get_by_client()` check and `create()` call. Concurrent Allocate
requests from the same client could both pass the check, both create allocations, inflate quota
counts, and leave orphaned allocations.

**FIX**:
- Added atomic `create_or_get()` method to AllocationTable using DashMap's entry API
- Updated handler to use `create_or_get()` and properly handle the `created=false` case
  by canceling rate limiter reservation and treating as retransmission

---

## Summary

| Issue | Severity | Status | Fix |
|-------|----------|--------|-----|
| 438 Stale Nonce missing REALM/NONCE | High | **VALID** | **FIXED** - New build_stale_nonce_response() |
| Send Indication missing touch_received() | Medium | **VALID** | **FIXED** - Added touch before early return |
| Allocation creation race condition | Medium | **VALID** | **FIXED** - Atomic create_or_get() |
