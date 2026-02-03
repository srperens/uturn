# Code Review 7

## Findings

- **Critical**: MESSAGE-INTEGRITY HMAC is computed/verified over the wrong bytes (the MESSAGE-INTEGRITY
  attribute header is excluded). That breaks RFC 5389 compliance and will cause auth failures with
  compliant clients (and could accept non-compliant ones). Affects both request validation and
  response generation. (`src/turn/handler.rs:119`, `src/turn/handler.rs:390`, `src/turn/handler.rs:1204`)

- **Medium**: SSRC tracking is unbounded. A permitted peer can send many distinct SSRCs, growing
  Allocation.ssrcs and by_ssrc without eviction; this is a memory DoS vector and the index isn't
  used in routing today. (`src/lookup/table.rs:139`, `src/relay/engine.rs:223`)

- **Low**: For long-term credentials, REALM is required, but requests missing REALM are currently
  accepted (if the HMAC matches). This is non-compliant and makes request validation weaker than
  spec. (`src/turn/handler.rs:103`, `src/turn/handler.rs:372`)

## Open Questions / Assumptions

- Assumed you want strict RFC 5389 behavior for long-term credentials; if compatibility with clients
  that omit REALM is intentional, the Low issue can be ignored.

---

## Validation Status

### 1. Critical: MESSAGE-INTEGRITY computation
**STATUS: INVESTIGATED - APPEARS CORRECT**

After careful analysis of RFC 5389 Section 15.4:

> "The text used as input to HMAC is the STUN message, including the header, up to and including
> the attribute preceding the MESSAGE-INTEGRITY attribute."

> "The length in the STUN header shall reflect the length of the message up to and including
> MESSAGE-INTEGRITY (not FINGERPRINT)."

The current implementation:
1. **HMAC input**: `msg.raw[..offset]` where offset is start of MESSAGE-INTEGRITY = header + all preceding attributes (NOT including MESSAGE-INTEGRITY)
2. **Length adjustment**: `(offset - 20 + 24)` = attributes before MI + MI size = includes MESSAGE-INTEGRITY

This matches RFC 5389 requirements. The MESSAGE-INTEGRITY attribute (including its 4-byte header)
should NOT be included in the HMAC input - only the preceding attributes with length adjusted to
point to end of MESSAGE-INTEGRITY.

**NO CHANGE MADE** - Implementation appears RFC compliant. If auth failures occur with real clients,
further investigation with captured packets and test vectors would be needed.

### 2. Medium: SSRC tracking unbounded
**STATUS: VALID**

`Allocation.ssrcs` is a HashSet that grows without limit. A malicious peer could send packets with
many unique SSRCs to cause unbounded memory growth.

**FIX**: Added `MAX_SSRCS_PER_ALLOCATION = 100` limit. The `register_ssrc()` method now returns
false and doesn't track SSRCs beyond this limit. Global `by_ssrc` index is only updated when
the allocation accepts the SSRC.

### 3. Low: REALM required but not enforced
**STATUS: VALID**

When using long-term credentials, RFC 5389 requires REALM in authenticated requests. The code was
accepting requests without REALM if the HMAC matched (using server's realm for key computation).

**FIX**: Added explicit check for REALM attribute. Requests without REALM now receive 401 Unauthorized
response with REALM and NONCE so client can retry properly.

---

## Summary

| Issue | Severity | Status | Fix |
|-------|----------|--------|-----|
| MESSAGE-INTEGRITY computation | Critical | **INVESTIGATED** | No change - appears RFC compliant |
| SSRC tracking unbounded | Medium | **VALID** | **FIXED** - Added MAX_SSRCS limit (100) |
| REALM not enforced | Low | **VALID** | **FIXED** - Reject requests missing REALM |
