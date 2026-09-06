//! TURN message handler

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, trace, warn};

use crate::config::Config;
use crate::demux::{StunClass, StunInfo, StunMethod};
use crate::lookup::{AllocationId, AllocationTable, RateLimitError, RateLimiter};

use super::auth::TurnAuth;
use super::message::TurnErrorCode;

/// TURN protocol handler
pub struct TurnHandler {
    config: Arc<Config>,
    allocations: Arc<AllocationTable>,
    rate_limiter: Arc<RateLimiter>,
}

/// Peer addresses we refuse to relay to, regardless of permission.
///
/// Loopback, multicast, broadcast and unspecified addresses either enable
/// reflection to services on the relay host or fan out amplification to the
/// local network. IPv4 link-local (169.254.0.0/16) covers AWS/GCE instance
/// metadata services.
pub(crate) fn is_forbidden_peer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) reaches the IPv4 host on
            // a dual-stack socket, so it must be judged by the IPv4 rules:
            // ::ffff:127.0.0.1 is loopback even though Ipv6Addr::is_loopback
            // says otherwise.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_peer_ip(IpAddr::V4(v4));
            }
            // fe80::/10 unicast link-local (no stable std predicate yet).
            let unicast_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() || unicast_link_local
        }
    }
}

/// Peer *transport addresses* we refuse to relay to.
///
/// Extends [`is_forbidden_peer_ip`] with the relay host's own external IP on
/// any port other than the relay port: `external_ip:relay_port` is the
/// legitimate single-port internal-routing target, everything else on that IP
/// would let a client reach other UDP services on the relay host. Applied to
/// Send indications, ChannelBind and the ChannelData egress alike so the two
/// data paths cannot be played against each other.
pub(crate) fn is_forbidden_peer_addr(config: &Config, addr: SocketAddr) -> bool {
    is_forbidden_peer_ip(addr.ip())
        || (addr.ip() == config.external_ip && addr.port() != config.port)
}

impl TurnHandler {
    /// Create a new handler
    pub fn new(
        config: Arc<Config>,
        allocations: Arc<AllocationTable>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            config,
            allocations,
            rate_limiter,
        }
    }

    /// Verify RFC 5389 long-term credentials on a request.
    ///
    /// Returns the authenticated username and its key on success, or the error
    /// response to send (401 with fresh REALM/NONCE, 438 Stale Nonce, or 400).
    /// Callers must have checked that credentials are configured at all.
    fn verify_long_term_credentials(&self, msg: &StunInfo) -> Result<(String, [u8; 16]), Vec<u8>> {
        // MESSAGE-INTEGRITY must be present: first contact gets a 401 challenge.
        if msg.message_integrity.is_none() {
            debug!("Request missing MESSAGE-INTEGRITY, sending 401 challenge");
            return Err(self.build_unauthorized_response(msg));
        }

        let username = match &msg.username {
            Some(u) => u,
            None => {
                warn!("Request has MESSAGE-INTEGRITY but no USERNAME");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        };

        let password = match self.config.get_password(username) {
            Some(p) => p,
            None => {
                warn!("Unknown username in authenticated request: {}", username);
                return Err(self.build_unauthorized_response(msg));
            }
        };

        // Validate nonce freshness
        match &msg.nonce {
            Some(nonce) => {
                if !TurnAuth::validate_nonce(
                    nonce,
                    self.config.nonce_lifetime_secs,
                    &self.config.nonce_secret,
                ) {
                    // 438 Stale Nonce must include REALM and fresh NONCE per RFC 5389
                    return Err(self.build_stale_nonce_response(msg));
                }
            }
            None => {
                warn!("Missing NONCE in authenticated request");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        }

        // Validate REALM - required for long-term credentials per RFC 5389
        match msg.realm.as_deref() {
            Some(realm) if realm != self.config.realm => {
                warn!(
                    "Realm mismatch: client sent '{}', expected '{}'",
                    realm, self.config.realm
                );
                return Err(self.build_unauthorized_response(msg));
            }
            None => {
                warn!("Missing REALM attribute in authenticated request");
                return Err(self.build_unauthorized_response(msg));
            }
            _ => {} // Realm matches
        }

        // Always use server's realm for key computation
        let key = TurnAuth::compute_key(username, &self.config.realm, password);

        let (integrity, offset) = match (&msg.message_integrity, msg.message_integrity_offset) {
            (Some(i), Some(o)) => (i, o),
            _ => {
                warn!("MESSAGE-INTEGRITY parsing error");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        };

        // Build message up to MESSAGE-INTEGRITY for validation. The header
        // length must be adjusted to end right after the MESSAGE-INTEGRITY
        // attribute: offset - 20 (header) + 24 (MESSAGE-INTEGRITY attr size).
        let mut msg_for_hmac = msg.raw[..offset].to_vec();
        let new_len = (offset - 20 + 24) as u16;
        msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());

        if !TurnAuth::verify_message_integrity(&msg_for_hmac, integrity, &key) {
            warn!("Invalid MESSAGE-INTEGRITY for user {}", username);
            return Err(self.build_unauthorized_response(msg));
        }

        debug!("MESSAGE-INTEGRITY validated for user {}", username);
        Ok((username.clone(), key))
    }

    /// Authenticate a request that operates on an existing allocation
    /// (Refresh, CreatePermission, ChannelBind) and resolve that allocation.
    ///
    /// RFC 5766 §10.1: every request after the initial Allocate carries the same
    /// credentials as the Allocate did, so the username must match the one on
    /// the allocation.
    ///
    /// Authentication deliberately runs *before* the allocation lookup. The
    /// lookup's own failure is a 437, and RFC 5389 §10.2.3 has an authenticated
    /// client discard an error response that carries no MESSAGE-INTEGRITY - so a
    /// 437 built without a key is invisible: the client retransmits through its
    /// whole RTO schedule (~39.5s) and reports a timeout instead of reallocating.
    /// Allocations here live at most 60s, so a client that loses one Refresh hits
    /// this on its next one.
    ///
    /// Returns the allocation id and the key every response on this request must
    /// be signed with (`None` in anonymous mode), or the error response to send.
    fn authenticate_for_allocation(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
    ) -> Result<(AllocationId, Option<[u8; 16]>), Vec<u8>> {
        let auth = if self.config.credentials.is_empty() {
            None
        } else {
            Some(self.verify_long_term_credentials(msg)?)
        };
        let key = auth.as_ref().map(|(_, k)| *k);

        // Snapshot id + username, then drop the guard: the caller awaits a send
        // on every path out of here and must not hold an allocation guard.
        let found = self
            .allocations
            .get_by_client(src_addr)
            .map(|a| (a.id, a.username.clone()));

        match (found, &auth) {
            (None, _) => {
                debug!("Request from {} has no allocation - 437", src_addr);
                Err(self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                ))
            }
            (Some((_, allocated_to)), Some((username, _))) if allocated_to != *username => {
                warn!(
                    "Username mismatch: allocation for {} belongs to '{}', request says '{}'",
                    src_addr, allocated_to, username
                );
                Err(self.build_unauthorized_response(msg))
            }
            (Some((id, _)), _) => Ok((id, key)),
        }
    }

    /// Handle incoming STUN/TURN message
    pub async fn handle_stun(
        &self,
        msg: StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        use crate::demux::stun::{StunClass, StunMethod};

        match (&msg.class, &msg.method) {
            // STUN Binding Request (ICE connectivity check)
            (StunClass::Request, StunMethod::Binding) => {
                self.handle_binding_request(&msg, src_addr, socket).await
            }

            // TURN Allocate
            (StunClass::Request, StunMethod::Allocate) => {
                self.handle_allocate(&msg, src_addr, socket).await
            }

            // TURN Refresh
            (StunClass::Request, StunMethod::Refresh) => {
                self.handle_refresh(&msg, src_addr, socket).await
            }

            // TURN CreatePermission
            (StunClass::Request, StunMethod::CreatePermission) => {
                self.handle_create_permission(&msg, src_addr, socket).await
            }

            // TURN ChannelBind
            (StunClass::Request, StunMethod::ChannelBind) => {
                self.handle_channel_bind(&msg, src_addr, socket).await
            }

            // TURN Send (client -> peer via indication)
            (StunClass::Indication, StunMethod::Send) => {
                self.handle_send(&msg, src_addr, socket).await
            }

            // Handle STUN responses from clients - relay them to peers
            (StunClass::SuccessResponse, _) | (StunClass::ErrorResponse, _) => {
                // If this is from a client with an allocation, relay to peers
                if self.allocations.lookup_by_source(src_addr).is_some() {
                    self.handle_client_response(&msg, src_addr, socket).await
                } else {
                    debug!(
                        "Unhandled STUN response: {:?} {:?} from {}",
                        msg.class, msg.method, src_addr
                    );
                    Ok(())
                }
            }

            _ => {
                debug!(
                    "Unhandled STUN message: {:?} {:?} from {}",
                    msg.class, msg.method, src_addr
                );
                Ok(())
            }
        }
    }

    /// Handle STUN Binding Request
    ///
    /// In single-port TURN, ICE connectivity checks may arrive as direct Binding Requests
    /// (not via Send Indication) because the remote relay address equals the TURN server address.
    /// We detect this case and relay the Binding Request to other clients.
    async fn handle_binding_request(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Binding request from {}", src_addr);

        // Non-TURN client (no allocation): respond with a normal Binding Response
        // (server reflexive). Membership is checked without holding a guard.
        if !self.allocations.is_client(src_addr) {
            let response = self.build_binding_response(msg, src_addr);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Sender is a TURN client doing ICE checks. Snapshot its id and current
        // relay permission, releasing the guard immediately: the relay paths below
        // await socket sends, and a guard must never be held across I/O.
        let (alloc_id, already_permitted) = match self.allocations.get_by_client(src_addr) {
            Some(a) => (a.id, a.is_permitted(self.config.external_ip)),
            None => {
                let response = self.build_binding_response(msg, src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Register ICE ufrags from USERNAME attribute (format: "remoteUfrag:localUfrag").
        // This is critical for single-port TURN to route DTLS/media correctly.
        if let Some((remote_ufrag, local_ufrag)) = msg.parse_ice_username() {
            let registered = self.allocations.register_ice_ufrags(
                alloc_id,
                local_ufrag.clone(),
                remote_ufrag.clone(),
            );
            if registered {
                debug!(
                    "Registered ICE ufrags for {}: local={}, remote={}",
                    src_addr, local_ufrag, remote_ufrag
                );
            }
        }

        // Auto-grant permission for relay IP if not already granted. This handles
        // the case where Chrome doesn't send CreatePermission when remote relay ==
        // local relay (single-port TURN).
        if !already_permitted {
            self.allocations
                .add_permission(alloc_id, self.config.external_ip);
            debug!(
                "Auto-granted permission for relay IP to allocation {}",
                alloc_id
            );
        }

        // Update the sender's activity timer and snapshot whether it is permitted
        // for the relay IP, then release the guard before any await.
        let sender_permitted = match self.allocations.get_by_client(src_addr) {
            Some(a) => {
                // Client is actively sending ICE checks
                a.touch_received();
                a.is_permitted(self.config.external_ip)
            }
            None => {
                let response = self.build_binding_response(msg, src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Relay to other allocations that share the relay-IP permission.
        if sender_permitted {
            let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

            // Snapshot the relay targets' client addresses without holding any
            // allocation guard across the awaits below.
            let targets: Vec<SocketAddr> = self
                .allocations
                .lookup_by_peer_ip(self.config.external_ip)
                .into_iter()
                .filter_map(|alloc_id| {
                    let target = self.allocations.get(alloc_id)?;
                    // Skip the sender's own allocation and targets without
                    // permission for the relay IP.
                    if target.client_addr == src_addr
                        || !target.is_permitted(self.config.external_ip)
                    {
                        None
                    } else {
                        Some(target.client_addr)
                    }
                })
                .collect();

            // Relay the Binding Request via Data Indication.
            // XOR-PEER-ADDRESS = relay address (from receiver's perspective).
            let indication = self.build_data_indication(relay_addr, &msg.raw);
            for target_addr in targets {
                debug!(
                    "Relaying Binding Request from {} to {} via Data Indication",
                    src_addr, target_addr
                );
                socket.send_to(&indication, target_addr).await?;
            }
        }

        // For TURN clients: don't respond ourselves - let the peer respond. This
        // allows consent freshness to work correctly (timeout if peer is gone).
        Ok(())
    }

    /// Handle STUN response from a client - relay to peers
    async fn handle_client_response(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Client response from {} - relaying to peers", src_addr);

        // Snapshot the target client addresses, then release all allocation
        // guards before awaiting the sends (never hold a guard across I/O).
        let targets: Vec<SocketAddr> = self
            .allocations
            .lookup_by_peer_ip(src_addr.ip())
            .into_iter()
            .filter_map(|alloc_id| {
                let target = self.allocations.get(alloc_id)?;
                // Skip if target is same as source
                if target.client_addr == src_addr {
                    None
                } else {
                    Some(target.client_addr)
                }
            })
            .collect();

        // Build and send Data Indication with the raw STUN response
        let indication = self.build_data_indication(src_addr, &msg.raw);
        for target_addr in targets {
            debug!(
                "Relaying response from {} to {} via Data Indication",
                src_addr, target_addr
            );
            socket.send_to(&indication, target_addr).await?;
        }

        Ok(())
    }

    /// Handle TURN Allocate Request
    ///
    /// Order follows RFC 5766 §6.2: authenticate first, then check the 5-tuple
    /// for an existing allocation, then validate the request, then admission
    /// control, then create.
    async fn handle_allocate(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        info!("Allocate request from {}", src_addr);

        // 1. Authenticate. Nothing below - including the retransmission shortcut -
        //    may act on a request whose MESSAGE-INTEGRITY has not been verified.
        let auth: Option<(String, [u8; 16])> = if self.config.credentials.is_empty() {
            None
        } else {
            match self.verify_long_term_credentials(msg) {
                Ok(v) => Some(v),
                Err(response) => {
                    debug!("Allocate auth failed from {}", src_addr);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            }
        };
        let key = auth.as_ref().map(|(_, k)| k);
        let username: String = match &auth {
            Some((u, _)) => u.clone(),
            // Anonymous mode: the (unauthenticated) USERNAME is informational only.
            None => msg.username.as_deref().unwrap_or("anonymous").to_string(),
        };

        // 2. Existing *live* allocation on this 5-tuple. A retransmission carries
        //    the same transaction id and gets the success response again; a *new*
        //    Allocate over a live allocation is a 437 Allocation Mismatch.
        //
        //    An allocation whose lifetime has run out but which cleanup_expired
        //    (2s interval) has not reaped yet is not live.
        let existing = self.allocations.get_by_client(src_addr).map(|a| {
            (
                a.id,
                a.is_expired(),
                a.allocate_txn_id == msg.transaction_id,
                a.remaining_lifetime(),
            )
        });

        // Reap a lapsed allocation rather than answer it: 437 would leave a
        // client that lets its allocation expire and reconnects unable to
        // allocate until the reaper catches up, and the success-with-lifetime-0
        // it used to get is just as dead. Releasing the quota slot here mirrors
        // what cleanup_expired would have done.
        if let Some((id, true, _, _)) = existing {
            if self.allocations.remove(id) {
                self.rate_limiter.record_deallocation(src_addr.ip());
                debug!(
                    "Reaped expired allocation {} for {} before re-Allocate",
                    id, src_addr
                );
            }
        } else if let Some((_, false, is_retransmission, lifetime)) = existing {
            if is_retransmission {
                debug!(
                    "Allocate retransmission from {} - resending success",
                    src_addr
                );
                let response = self.build_allocate_response(msg, src_addr, lifetime, key);
                socket.send_to(&response, src_addr).await?;
            } else {
                warn!(
                    "Allocate from {} with a new transaction id over an existing allocation - 437",
                    src_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::AllocationMismatch, key);
                socket.send_to(&response, src_addr).await?;
            }
            return Ok(());
        }

        // 3. Validate REQUESTED-TRANSPORT (RFC 5766 requires UDP = 17)
        match msg.requested_transport {
            Some(17) => {
                // UDP is supported
            }
            Some(other) => {
                warn!("Unsupported transport protocol {} from {}", other, src_addr);
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::UnsupportedTransport, key);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            None => {
                // Per RFC 5766, REQUESTED-TRANSPORT is required. However, some clients
                // may omit it for UDP-only servers. We'll be lenient and assume UDP.
                debug!("Allocate request missing REQUESTED-TRANSPORT, assuming UDP");
            }
        }

        // 4. Admission control. Runs after auth so that auth failures return 401,
        //    not 508/486, and only valid attempts count against the limits.
        if let Err(e) = self.rate_limiter.check_allocation_request(src_addr.ip()) {
            warn!("Allocate request rejected for {}: {}", src_addr, e);
            let error_code = match e {
                RateLimitError::TooManyRequests => TurnErrorCode::InsufficientCapacity,
                RateLimitError::QuotaExceeded => TurnErrorCode::AllocationQuotaReached,
            };
            let response = self.build_signed_error_response(msg, error_code, key);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // 5. Create the allocation atomically, remembering the transaction id so
        //    retransmissions can be recognised in step 2.
        let lifetime = 60;
        let (alloc_id, created) = self.allocations.create_or_get(
            src_addr,
            username.clone(),
            lifetime,
            msg.transaction_id,
        );

        if !created {
            // Concurrent request won the race - treat as retransmission and
            // cancel our rate limiter reservation since nothing new was created.
            debug!(
                "Concurrent allocation created for {} - treating as retransmission",
                src_addr
            );
            self.rate_limiter.cancel_reservation(src_addr.ip());
        } else {
            info!(
                "Created allocation {} for {} (user: {})",
                alloc_id, src_addr, username
            );
        }

        // Get actual lifetime from allocation (may be different if existing)
        let actual_lifetime = self
            .allocations
            .get(alloc_id)
            .map(|a| a.remaining_lifetime())
            .unwrap_or(lifetime);

        let response = self.build_allocate_response(msg, src_addr, actual_lifetime, key);
        debug!(
            "Sending Allocate response ({} bytes) to {}: {:02x?}",
            response.len(),
            src_addr,
            &response[..std::cmp::min(response.len(), 64)]
        );
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Refresh Request
    async fn handle_refresh(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Refresh request from {}", src_addr);

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("Refresh from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse requested lifetime (0 means delete allocation)
        let requested_lifetime = msg.lifetime.unwrap_or(60);

        if requested_lifetime == 0 {
            // Client wants to delete the allocation. Only release the quota
            // slot if *we* removed it: if cleanup reaped it concurrently, the
            // cleanup task already released the slot and a second decrement
            // would let this IP exceed its allocation quota.
            if self.allocations.remove(alloc_id) {
                self.rate_limiter.record_deallocation(src_addr.ip());
                info!(
                    "Deleted allocation {} for {} (lifetime=0)",
                    alloc_id, src_addr
                );
            } else {
                debug!(
                    "Allocation {} for {} already removed before lifetime=0 refresh",
                    alloc_id, src_addr
                );
            }

            let response = self.build_refresh_response(msg, 0, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Cap lifetime at 60 seconds max, minimum 10 seconds
        let lifetime = requested_lifetime.clamp(10, 60);
        // Re-acquire briefly to extend the lifetime and activity timer; if the
        // allocation was reaped concurrently we simply skip the update.
        if let Some(alloc) = self.allocations.get_by_client(src_addr) {
            alloc.refresh(lifetime);
            alloc.touch_received();
        }

        debug!(
            "Refreshed allocation for {} (lifetime={}s)",
            src_addr, lifetime
        );

        let response = self.build_refresh_response(msg, lifetime, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN CreatePermission Request
    async fn handle_create_permission(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("CreatePermission request from {}", src_addr);

        // Parse XOR-PEER-ADDRESS attributes first (can have multiple)
        if msg.xor_peer_addresses.is_empty() {
            warn!(
                "CreatePermission missing XOR-PEER-ADDRESS from {}",
                src_addr
            );
            let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("CreatePermission from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Reject forbidden peer IPs. RFC 5766 §9.2 permits the server to reject
        // any peer address it does not wish to relay to; 403 covers
        // loopback/multicast/etc. Runs after authentication so the response can
        // be signed - an unsigned 403 is discarded by an authenticated client.
        for peer_addr in &msg.xor_peer_addresses {
            if is_forbidden_peer_ip(peer_addr.ip()) {
                warn!(
                    "CreatePermission with forbidden peer {} from {}",
                    peer_addr.ip(),
                    src_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::Forbidden, key.as_ref());
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        }

        if let Some(alloc) = self.allocations.get(alloc_id) {
            alloc.touch_received();
        }

        // Atomically enforce the per-allocation permission cap and insert the
        // new peer IPs. Re-adds of existing permissions are always allowed
        // (refresh semantics). Holding the write lock across the count check
        // and insert avoids TOCTOU against concurrent CreatePermission requests.
        let peer_ips: Vec<IpAddr> = msg.xor_peer_addresses.iter().map(|a| a.ip()).collect();
        if !self.allocations.try_add_permissions_capped(
            alloc_id,
            &peer_ips,
            self.config.max_permissions_per_alloc,
        ) {
            warn!(
                "CreatePermission cap exceeded for {} (alloc {}, max {})",
                src_addr, alloc_id, self.config.max_permissions_per_alloc
            );
            let response = self.build_signed_error_response(
                msg,
                TurnErrorCode::InsufficientCapacity,
                key.as_ref(),
            );
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        info!(
            "CreatePermission: added/refreshed {} peer(s) for {} (alloc {})",
            peer_ips.len(),
            src_addr,
            alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN ChannelBind Request
    async fn handle_channel_bind(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("ChannelBind request from {}", src_addr);

        // Parse CHANNEL-NUMBER
        let channel = match msg.channel_number {
            Some(ch) => ch,
            None => {
                warn!("ChannelBind missing CHANNEL-NUMBER from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse XOR-PEER-ADDRESS (ChannelBind uses only one peer address)
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("ChannelBind missing XOR-PEER-ADDRESS from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("ChannelBind from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Runs after authentication so the 403 can be signed - an unsigned error
        // response is discarded by an authenticated client (RFC 5389 §10.2.3).
        if is_forbidden_peer_addr(&self.config, peer_addr) {
            warn!(
                "ChannelBind with forbidden peer {} from {}",
                peer_addr, src_addr
            );
            let response =
                self.build_signed_error_response(msg, TurnErrorCode::Forbidden, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        /// Outcome of the bind check, decided under one short-lived guard.
        enum Bind {
            /// Admissible. `needs_bind` is false for a refresh of the same pair.
            Ok {
                needs_bind: bool,
            },
            /// Channel bound to another peer, or peer bound to another channel.
            Conflict,
            CapExceeded(usize),
            Gone,
        }

        // Decide the outcome before mutating anything. RFC 5766 §11.2 requires an
        // error response to leave the allocation untouched; installing the implied
        // permission up front let a client fill its permission table with IPs
        // through ChannelBinds the server goes on to reject.
        let outcome = match self.allocations.get(alloc_id) {
            Some(alloc) => {
                let bound_peer = alloc.peer_for_channel(channel);
                let bound_channel = alloc.channel_for_peer(peer_addr);
                match (bound_peer, bound_channel) {
                    // RFC 5766 §11.2: a channel may not be rebound to a different
                    // peer, nor a peer to a different channel, while bound.
                    (Some(p), _) if p != peer_addr => Bind::Conflict,
                    (_, Some(c)) if c != channel => Bind::Conflict,
                    // Identical binding: refresh, consumes no new slot.
                    (Some(_), Some(_)) => Bind::Ok { needs_bind: false },
                    _ if alloc.channels_count() >= self.config.max_channels_per_alloc => {
                        Bind::CapExceeded(alloc.channels_count())
                    }
                    _ => Bind::Ok { needs_bind: true },
                }
            }
            None => Bind::Gone,
        };

        let needs_bind = match outcome {
            Bind::Ok { needs_bind } => needs_bind,
            Bind::Conflict => {
                warn!(
                    "ChannelBind conflict from {}: channel 0x{:04x} / peer {} already bound elsewhere",
                    src_addr, channel, peer_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::BadRequest, key.as_ref());
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            Bind::CapExceeded(count) => {
                warn!(
                    "ChannelBind cap exceeded for {}: {} >= {}",
                    src_addr, count, self.config.max_channels_per_alloc
                );
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::InsufficientCapacity,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            Bind::Gone => {
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // ChannelBind also installs (or refreshes) a permission for the peer IP
        // (RFC 5766 §11.2). Go through the capped path so ChannelBind cannot be
        // used to bypass the per-allocation permission cap.
        if !self.allocations.try_add_permissions_capped(
            alloc_id,
            &[peer_addr.ip()],
            self.config.max_permissions_per_alloc,
        ) {
            let (code, what) = if self.allocations.get(alloc_id).is_none() {
                (TurnErrorCode::AllocationMismatch, "allocation gone")
            } else {
                (
                    TurnErrorCode::InsufficientCapacity,
                    "permission cap exceeded",
                )
            };
            warn!("ChannelBind from {} rejected: {}", src_addr, what);
            let response = self.build_signed_error_response(msg, code, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Commit the binding. The permission is in place, so a client that gets
        // a success response can use the channel immediately.
        match self.allocations.get(alloc_id) {
            Some(alloc) => {
                if needs_bind {
                    alloc.bind_channel(channel, peer_addr);
                }
                alloc.touch_received();
            }
            None => {
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        }

        info!(
            "ChannelBind: channel 0x{:04x} -> {} for {} (alloc {})",
            channel, peer_addr, src_addr, alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Send Indication
    async fn handle_send(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Send indication from {}", src_addr);

        // This client must have an allocation. We deliberately do NOT hold the
        // allocation guard across this function: the relay paths below await
        // socket sends, and an allocation guard must never be held across I/O.
        // Each branch re-acquires the allocation briefly as needed.
        if !self.allocations.is_client(src_addr) {
            trace!("Send indication from unknown client: {}", src_addr);
            return Ok(());
        }

        // Get peer address
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("Send indication missing XOR-PEER-ADDRESS from {}", src_addr);
                return Ok(());
            }
        };

        // Reject forbidden peer targets: loopback, multicast, broadcast, link-
        // local, and our own external IP on a non-relay port. Same IP + relay
        // port is the legitimate single-port internal-routing case handled below.
        if is_forbidden_peer_addr(&self.config, peer_addr) {
            warn!(
                "Send indication to forbidden peer {} from {}",
                peer_addr, src_addr
            );
            return Ok(());
        }

        // Prevent sending to ourselves (would create a loop)
        let our_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        if peer_addr == our_addr {
            // This is valid in single-port TURN - both clients may have the same relay address
            // In this case, we need to find OTHER allocations that have permission for our relay
            // and send the data to them
            debug!("Send to our own relay address - routing internally");

            // Snapshot the sender's permission + id, then release the guard before
            // any await below (never hold an allocation guard across socket I/O).
            let (sender_permitted, alloc_id) = match self.allocations.get_by_client(src_addr) {
                Some(a) => (a.is_permitted(self.config.external_ip), a.id),
                None => return Ok(()),
            };

            // Check that the SENDER has permission for the relay IP (RFC 5766 requirement)
            if !sender_permitted {
                warn!(
                    "Send indication to relay address from {} without permission",
                    src_addr
                );
                return Ok(());
            }

            let data = match &msg.data {
                Some(d) => d,
                None => return Ok(()),
            };

            // Try targeted routing via ICE ufrags to avoid cross-talk between
            // unrelated calls. Only fall back to broadcast for the very first
            // STUN packet before any ufrag is registered.
            let mut sent = false;

            // For STUN Binding Requests: register sender ufrags and route by target ufrag
            if let Some(stun_info) = StunInfo::parse(data) {
                if stun_info.method == StunMethod::Binding && stun_info.class == StunClass::Request
                {
                    if let Some((remote_ufrag, local_ufrag)) = stun_info.parse_ice_username() {
                        let registered = self.allocations.register_ice_ufrags(
                            alloc_id,
                            local_ufrag.clone(),
                            remote_ufrag.clone(),
                        );
                        if registered {
                            debug!(
                                "ICE registration (Send indication): {} local={}, remote={}",
                                src_addr, local_ufrag, remote_ufrag
                            );
                        }

                        // Route to target by their ICE ufrag: snapshot its address,
                        // release the guard, then await.
                        let target_addr = self
                            .allocations
                            .lookup_by_ice_ufrag(&remote_ufrag)
                            .and_then(|target_id| {
                                let target = self.allocations.get(target_id)?;
                                if target.client_addr != src_addr
                                    && target.is_permitted(self.config.external_ip)
                                {
                                    Some(target.client_addr)
                                } else {
                                    None
                                }
                            });
                        if let Some(target_addr) = target_addr {
                            let indication = self.build_data_indication(our_addr, data);
                            socket.send_to(&indication, target_addr).await?;
                            sent = true;
                        }
                    }
                }
            }

            // For non-STUN or STUN responses: use ICE peer matching. Read the
            // sender's ufrags fresh (the block above may have just registered
            // them), then snapshot peer addresses before awaiting.
            if !sent {
                let (sender_local, sender_remote) = match self.allocations.get_by_client(src_addr) {
                    Some(a) => (a.get_ice_ufrag(), a.get_ice_remote_ufrag()),
                    None => (None, None),
                };
                if let (Some(local), Some(remote)) = (&sender_local, &sender_remote) {
                    let targets: Vec<SocketAddr> = self
                        .allocations
                        .find_ice_peers(local, remote)
                        .into_iter()
                        .filter_map(|peer_id| {
                            let target = self.allocations.get(peer_id)?;
                            if target.client_addr != src_addr
                                && target.is_permitted(self.config.external_ip)
                            {
                                Some(target.client_addr)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !targets.is_empty() {
                        let indication = self.build_data_indication(our_addr, data);
                        for target_addr in targets {
                            socket.send_to(&indication, target_addr).await?;
                            sent = true;
                        }
                    }
                }
            }

            // Last resort: send only to unpaired allocations (no ice_ufrag set yet).
            // This limits the broadcast to allocations that haven't completed ICE,
            // preventing leakage to already-established calls.
            if !sent {
                // Snapshot unpaired target addresses before awaiting.
                let targets: Vec<SocketAddr> = self
                    .allocations
                    .lookup_by_peer_ip(self.config.external_ip)
                    .into_iter()
                    .filter_map(|alloc_id| {
                        let target = self.allocations.get(alloc_id)?;
                        // Skip the sender and allocations that already have ICE
                        // ufrags (established calls).
                        if target.client_addr == src_addr || target.get_ice_ufrag().is_some() {
                            None
                        } else {
                            Some(target.client_addr)
                        }
                    })
                    .collect();
                let indication = self.build_data_indication(our_addr, data);
                for target_addr in targets {
                    socket.send_to(&indication, target_addr).await?;
                    sent = true;
                }
                if !sent {
                    trace!(
                        "No unpaired target found for internal routing from {}",
                        src_addr
                    );
                }
            }

            // Touch sender's allocation - they're actively sending data. A
            // successful internal route also feeds the orphan-sender timer, but a
            // failed one deliberately does not: the payload here is usually an ICE
            // connectivity check, sent before any peer exists, so arming the timer
            // would have cleanup_orphaned_senders reap the allocation of whoever
            // joins first (ringing, waiting room, slow signalling) 45s later,
            // while it is actively sending and refreshing. The ChannelData and raw
            // media paths do arm it on a failed relay, but STUN never reaches
            // them - engine.rs routes ICE in its own branch and server.rs only
            // sees RTP/RTCP/DTLS - so by then the client is past ICE.
            if let Some(a) = self.allocations.get_by_client(src_addr) {
                a.touch_received();
                if sent {
                    a.touch_relay_success();
                }
            }
            return Ok(());
        }

        // Get data
        let data = match &msg.data {
            Some(d) => d,
            None => {
                trace!("Send indication missing DATA from {}", src_addr);
                return Ok(());
            }
        };

        // Check permission (snapshot, then release the guard before the await).
        let permitted = match self.allocations.get_by_client(src_addr) {
            Some(a) => a.is_permitted(peer_addr.ip()),
            None => return Ok(()),
        };
        if !permitted {
            warn!(
                "Send indication to unpermitted peer {} from {}",
                peer_addr, src_addr
            );
            return Ok(());
        }

        // Relay data to peer. If the peer is another TURN client of this server,
        // a raw datagram would arrive on its TURN control socket from our relay
        // address and be discarded by its TURN stack; wrap it in ChannelData or
        // a Data Indication exactly as the ChannelData path in the relay engine
        // does. Snapshot the target under a short guard, release, then send.
        let target = self
            .allocations
            .get_by_client(peer_addr)
            .map(|t| (t.id, t.channel_for_peer(src_addr)));
        match target {
            Some((target_id, reverse_channel)) => {
                debug!(
                    "Relaying {} bytes from {} to TURN client {} via {}",
                    data.len(),
                    src_addr,
                    peer_addr,
                    match reverse_channel {
                        Some(c) => format!("reverse channel 0x{:04x}", c),
                        None => "Data Indication".to_string(),
                    }
                );
                let packet = match reverse_channel {
                    Some(c) => self.build_channel_data(c, data),
                    None => self.build_data_indication(src_addr, data),
                };
                socket.send_to(&packet, peer_addr).await?;
                if let Some(t) = self.allocations.get(target_id) {
                    t.touch();
                }
            }
            None => {
                debug!(
                    "Relaying {} bytes from {} to peer {}",
                    data.len(),
                    src_addr,
                    peer_addr
                );
                socket.send_to(data, peer_addr).await?;
            }
        }

        // Touch sender's allocation - they're actively sending data
        if let Some(a) = self.allocations.get_by_client(src_addr) {
            a.touch_received();
        }

        Ok(())
    }

    /// Build a STUN Binding Response
    fn build_binding_response(&self, request: &StunInfo, client_addr: SocketAddr) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        // Message type: Binding Success Response (0x0101)
        response.extend_from_slice(&[0x01, 0x01]);

        // Placeholder for length (will be filled later)
        response.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID
        response.extend_from_slice(&request.transaction_id);

        // XOR-MAPPED-ADDRESS attribute
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a TURN Allocate Success Response
    fn build_allocate_response(
        &self,
        request: &StunInfo,
        client_addr: SocketAddr,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(96);

        // Message type: Allocate Success Response (0x0103)
        response.extend_from_slice(&[0x01, 0x03]);
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        response.extend_from_slice(&request.transaction_id);

        // XOR-RELAYED-ADDRESS (our single port!)
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        self.append_xor_relayed_address(&mut response, relay_addr, &request.transaction_id);

        // XOR-MAPPED-ADDRESS
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a TURN Refresh Success Response
    fn build_refresh_response(
        &self,
        request: &StunInfo,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Message type: Refresh Success Response (0x0104)
        response.extend_from_slice(&[0x01, 0x04]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a generic success response
    fn build_success_response(&self, request: &StunInfo, key: Option<&[u8; 16]>) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Success response: set bit 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let success_type = msg_type | 0x0100;

        response.extend_from_slice(&success_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build an error response without MESSAGE-INTEGRITY.
    ///
    /// Only for errors raised before the credentials were verified, where no
    /// key is available. Anything answered after authentication goes through
    /// [`Self::build_signed_error_response`].
    fn build_error_response(&self, request: &StunInfo, error: TurnErrorCode) -> Vec<u8> {
        self.build_signed_error_response(request, error, None)
    }

    /// Build an error response, signed when the request was authenticated.
    ///
    /// RFC 5389 Section 10.2.3: a client using long-term credentials discards an
    /// error response that carries no MESSAGE-INTEGRITY, except for 400, 401 and
    /// 438. An unsigned 437 or 508 is therefore invisible to the client - it keeps
    /// retransmitting until its RTO schedule runs out (~39.5s) and then reports a
    /// plain timeout instead of the error we sent.
    fn build_signed_error_response(
        &self,
        request: &StunInfo,
        error: TurnErrorCode,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(48);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009)
        let reason = error.reason();
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes()); // Length
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push((error as u16 / 100) as u8); // Class
        response.push((error as u16 % 100) as u8); // Number
        response.extend_from_slice(reason.as_bytes());

        // Padding (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Append XOR-MAPPED-ADDRESS attribute
    fn append_xor_mapped_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0020
        buf.extend_from_slice(&[0x00, 0x20]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length = 8
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4 family

                // XOR port with magic cookie upper 16 bits
                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie
                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                // XOR port with magic cookie upper 16 bits
                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie (4 bytes) + transaction ID (12 bytes)
                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }

    /// Append XOR-RELAYED-ADDRESS attribute
    fn append_xor_relayed_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0016
        buf.extend_from_slice(&[0x00, 0x16]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]);
                buf.push(0x00);
                buf.push(0x01);

                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }

    /// Append LIFETIME attribute
    fn append_lifetime(&self, buf: &mut Vec<u8>, lifetime: u32) {
        buf.extend_from_slice(&[0x00, 0x0d]); // Type
        buf.extend_from_slice(&[0x00, 0x04]); // Length
        buf.extend_from_slice(&lifetime.to_be_bytes());
    }

    /// Build a 401 Unauthorized response with REALM and NONCE
    fn build_unauthorized_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 401 Unauthorized
        let reason = "Unauthorized";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (401 / 100)
        response.push(1); // Number (401 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a 438 Stale Nonce response with REALM and fresh NONCE
    ///
    /// Per RFC 5389, 438 responses must include REALM and NONCE so clients
    /// can retry with the new nonce.
    fn build_stale_nonce_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 438 Stale Nonce
        let reason = "Stale Nonce";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (438 / 100)
        response.push(38); // Number (438 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute - required for client to retry
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute - fresh nonce for client to use
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Append REALM attribute (0x0014)
    fn append_realm(&self, buf: &mut Vec<u8>, realm: &str) {
        let realm_bytes = realm.as_bytes();
        let padded_len = (realm_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x14]); // Type
        buf.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(realm_bytes);

        // Padding
        for _ in realm_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append NONCE attribute (0x0015)
    fn append_nonce(&self, buf: &mut Vec<u8>, nonce: &str) {
        let nonce_bytes = nonce.as_bytes();
        let padded_len = (nonce_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x15]); // Type
        buf.extend_from_slice(&(nonce_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(nonce_bytes);

        // Padding
        for _ in nonce_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append MESSAGE-INTEGRITY attribute (0x0008)
    fn append_message_integrity(&self, buf: &mut Vec<u8>, key: &[u8; 16]) {
        // First, update the length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
        let new_len = (buf.len() - 20 + 24) as u16;
        buf[2..4].copy_from_slice(&new_len.to_be_bytes());

        // Compute HMAC-SHA1 over message up to this point
        let integrity = TurnAuth::compute_message_integrity(buf, key);

        // Append MESSAGE-INTEGRITY attribute
        buf.extend_from_slice(&[0x00, 0x08]); // Type
        buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
        buf.extend_from_slice(&integrity);
    }

    /// Build a TURN ChannelData message (RFC 5766 §11.4)
    fn build_channel_data(&self, channel: u16, data: &[u8]) -> Vec<u8> {
        let padding = (4 - ((4 + data.len()) % 4)) % 4;
        let mut packet = Vec::with_capacity(4 + data.len() + padding);
        packet.extend_from_slice(&channel.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
        packet.resize(packet.len() + padding, 0);
        packet
    }

    /// Build a TURN Data Indication
    fn build_data_indication(&self, peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(48 + data.len());

        // Data Indication: 0x0017
        packet.extend_from_slice(&[0x00, 0x17]);

        // Length placeholder
        packet.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        packet.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID (random for indication per RFC 5389)
        let txn_id: [u8; 12] = rand::random();
        packet.extend_from_slice(&txn_id);

        // XOR-PEER-ADDRESS attribute (0x0012)
        self.append_xor_peer_address(&mut packet, peer_addr, &txn_id);

        // DATA attribute (0x0013)
        packet.extend_from_slice(&[0x00, 0x13]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad DATA attribute
        while (packet.len() - 20) % 4 != 0 {
            packet.push(0);
        }

        // Update length
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        packet
    }

    /// Append XOR-PEER-ADDRESS attribute (0x0012)
    fn append_xor_peer_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        buf.extend_from_slice(&[0x00, 0x12]); // Type

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4

                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_forbidden_peer_ip;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_ipv4_loopback() {
        assert!(is_forbidden_peer_ip(ip("127.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("127.0.0.2")));
        assert!(is_forbidden_peer_ip(ip("127.255.255.254")));
    }

    #[test]
    fn forbidden_ipv4_multicast_and_broadcast() {
        assert!(is_forbidden_peer_ip(ip("224.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("239.255.255.255")));
        assert!(is_forbidden_peer_ip(ip("255.255.255.255")));
    }

    #[test]
    fn forbidden_ipv4_unspecified() {
        assert!(is_forbidden_peer_ip(ip("0.0.0.0")));
    }

    #[test]
    fn forbidden_ipv4_link_local_covers_cloud_metadata() {
        // AWS/GCE/Azure instance metadata: 169.254.169.254
        assert!(is_forbidden_peer_ip(ip("169.254.169.254")));
        assert!(is_forbidden_peer_ip(ip("169.254.0.1")));
    }

    #[test]
    fn forbidden_ipv6_loopback_and_multicast_and_unspecified() {
        assert!(is_forbidden_peer_ip(ip("::1")));
        assert!(is_forbidden_peer_ip(ip("ff02::1")));
        assert!(is_forbidden_peer_ip(ip("::")));
    }

    #[test]
    fn forbidden_ipv4_mapped_ipv6_judged_by_ipv4_rules() {
        assert!(is_forbidden_peer_ip(ip("::ffff:127.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("::ffff:169.254.169.254")));
        assert!(is_forbidden_peer_ip(ip("::ffff:224.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("::ffff:0.0.0.0")));
        // Mapped global unicast stays allowed.
        assert!(!is_forbidden_peer_ip(ip("::ffff:203.0.113.5")));
    }

    #[test]
    fn forbidden_ipv6_unicast_link_local() {
        assert!(is_forbidden_peer_ip(ip("fe80::1")));
        assert!(is_forbidden_peer_ip(ip("febf::1")));
        // fec0::/10 (deprecated site-local) is not link-local.
        assert!(!is_forbidden_peer_ip(ip("fec0::1")));
    }

    #[test]
    fn forbidden_peer_addr_blocks_own_external_ip_on_other_ports() {
        use super::is_forbidden_peer_addr;
        use crate::config::Config;
        let cfg = Config::new(ip("203.0.113.10")).with_port(3478);
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        // Relay address itself is the legitimate single-port target.
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.10:3478")));
        // Any other port on the relay host is refused.
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:53")));
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:3479")));
        // IP-level rules still apply.
        assert!(is_forbidden_peer_addr(&cfg, sa("127.0.0.1:3478")));
        // Unrelated hosts are fine on any port.
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.11:53")));
    }

    #[test]
    fn allowed_global_unicast_not_forbidden() {
        assert!(!is_forbidden_peer_ip(ip("8.8.8.8")));
        assert!(!is_forbidden_peer_ip(ip("203.0.113.5"))); // TEST-NET-3
        assert!(!is_forbidden_peer_ip(ip("2001:db8::1")));
    }

    // ---- helpers for the handler-level tests below -------------------------

    use super::{
        AllocationTable, Config, RateLimiter, StunClass, StunInfo, StunMethod, TurnAuth,
        TurnErrorCode, TurnHandler,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;

    const RELAY_IP: &str = "203.0.113.10";
    const RELAY_PORT: u16 = 3478;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Handler over an anonymous (no credentials) config, so the tests exercise
    /// the request logic rather than the authentication path.
    fn handler() -> (TurnHandler, Arc<AllocationTable>) {
        let config = Arc::new(Config::new(ip(RELAY_IP)).with_port(RELAY_PORT));
        let allocations = Arc::new(AllocationTable::new());
        let rate_limiter = Arc::new(RateLimiter::new(120, 100));
        (
            TurnHandler::new(config, Arc::clone(&allocations), rate_limiter),
            allocations,
        )
    }

    /// Minimal parsed request. Attributes are set by the caller; only `raw`'s
    /// message type and transaction id matter for building a response.
    fn request(method: StunMethod, msg_type: u16) -> StunInfo {
        let transaction_id = [7u8; 12];
        let mut raw = Vec::with_capacity(20);
        raw.extend_from_slice(&msg_type.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00]);
        raw.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        raw.extend_from_slice(&transaction_id);
        StunInfo {
            class: StunClass::Request,
            method,
            transaction_id,
            username: None,
            xor_peer_addresses: Vec::new(),
            channel_number: None,
            lifetime: None,
            data: None,
            realm: None,
            nonce: None,
            message_integrity: None,
            message_integrity_offset: None,
            requested_transport: None,
            raw,
        }
    }

    // ---- error responses ----------------------------------------------------

    #[test]
    fn signed_error_response_carries_verifiable_message_integrity() {
        // RFC 5389 §10.2.3: a client that authenticated discards an error
        // response without MESSAGE-INTEGRITY (except 400/401/438), so a 437 has
        // to be signed or the client just retransmits until it times out.
        let (h, _) = handler();
        let msg = request(StunMethod::Allocate, 0x0003);
        let key = TurnAuth::compute_key("user", "uturn", "pass");

        let resp =
            h.build_signed_error_response(&msg, TurnErrorCode::AllocationMismatch, Some(&key));

        // Header length covers everything after the 20-byte header.
        let declared = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(declared, resp.len() - 20);

        // MESSAGE-INTEGRITY is the trailing 24-byte attribute (4 + 20).
        let mi_start = resp.len() - 24;
        assert_eq!(&resp[mi_start..mi_start + 2], &[0x00, 0x08]);
        assert_eq!(&resp[mi_start + 2..mi_start + 4], &[0x00, 0x14]);
        assert!(TurnAuth::verify_message_integrity(
            &resp[..mi_start],
            &resp[mi_start + 4..],
            &key
        ));

        // ERROR-CODE still says 437.
        assert_eq!(&resp[20..22], &[0x00, 0x09]);
        assert_eq!(resp[24 + 2], 4);
        assert_eq!(resp[24 + 3], 37);
    }

    #[test]
    fn unsigned_error_response_has_no_message_integrity() {
        let (h, _) = handler();
        let msg = request(StunMethod::Allocate, 0x0003);
        let resp = h.build_error_response(&msg, TurnErrorCode::AllocationMismatch);
        let declared = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(declared, resp.len() - 20);

        // Same message, 24 bytes shorter than the signed one, and its trailing
        // attribute is the ERROR-CODE rather than a MESSAGE-INTEGRITY.
        let key = TurnAuth::compute_key("user", "uturn", "pass");
        let signed =
            h.build_signed_error_response(&msg, TurnErrorCode::AllocationMismatch, Some(&key));
        assert_eq!(signed.len(), resp.len() + 24);
        assert_eq!(&resp[20..22], &[0x00, 0x09]);
        let attr_len = u16::from_be_bytes([resp[22], resp[23]]) as usize;
        assert_eq!(resp.len(), 20 + 4 + attr_len.div_ceil(4) * 4);
    }

    // ---- ChannelBind --------------------------------------------------------

    #[tokio::test]
    async fn channel_bind_conflict_installs_no_permission() {
        // RFC 5766 §11.2: an error response must leave the allocation unchanged.
        // The permission implied by ChannelBind used to be installed before the
        // binding was validated, so a client could fill its permission table
        // with IPs through requests the server went on to reject with 400.
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40001");
        let id = table.create(client, "u".to_string(), 600);

        let peer_a = sa("203.0.113.20:5000");
        let peer_b = sa("203.0.113.21:5000");

        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![peer_a];
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer_a));
        assert_eq!(alloc.permissions_count(), 1);
        drop(alloc);

        // Same channel, different peer -> 400, and no trace of peer_b.
        bind.xor_peer_addresses = vec![peer_b];
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer_a));
        assert_eq!(alloc.channel_for_peer(peer_b), None);
        assert!(!alloc.is_permitted(peer_b.ip()));
        assert_eq!(alloc.permissions_count(), 1);
    }

    #[tokio::test]
    async fn channel_bind_refresh_of_same_pair_is_idempotent() {
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40002");
        let id = table.create(client, "u".to_string(), 600);

        let peer = sa("203.0.113.20:5000");
        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![peer];

        h.handle_channel_bind(&bind, client, &socket).await.unwrap();
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer));
        assert_eq!(alloc.channels_count(), 1);
        assert_eq!(alloc.permissions_count(), 1);
    }

    // ---- authenticated requests --------------------------------------------

    const USER: &str = "user";
    const PASS: &str = "pass";

    /// Handler with one static credential configured, plus the key that user
    /// signs with. Responses to its requests must carry MESSAGE-INTEGRITY.
    fn auth_handler() -> (TurnHandler, Arc<AllocationTable>, Arc<Config>, [u8; 16]) {
        let config = Arc::new(
            Config::new(ip(RELAY_IP))
                .with_port(RELAY_PORT)
                .with_credential(USER, PASS),
        );
        let allocations = Arc::new(AllocationTable::new());
        let rate_limiter = Arc::new(RateLimiter::new(120, 100));
        let key = TurnAuth::compute_key(USER, &config.realm, PASS);
        (
            TurnHandler::new(Arc::clone(&config), Arc::clone(&allocations), rate_limiter),
            allocations,
            config,
            key,
        )
    }

    /// Add the credential attributes and a MESSAGE-INTEGRITY over `raw`, the way
    /// a client would. `raw` holds only the header, which is all the server
    /// hashes here; the parsed attributes are set as fields.
    fn sign(mut msg: StunInfo, config: &Config, key: &[u8; 16]) -> StunInfo {
        msg.username = Some(USER.to_string());
        msg.realm = Some(config.realm.clone());
        msg.nonce = Some(TurnAuth::generate_nonce(&config.nonce_secret));

        let offset = msg.raw.len();
        let hashed_len = (offset - 20 + 24) as u16;
        msg.raw[2..4].copy_from_slice(&hashed_len.to_be_bytes());
        let mi = TurnAuth::compute_message_integrity(&msg.raw, key);
        msg.raw.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        msg.raw.extend_from_slice(&mi);
        msg.message_integrity = Some(mi.to_vec());
        msg.message_integrity_offset = Some(offset);
        msg
    }

    /// Bind a socket for the server and one standing in for the client, and
    /// return the client's address so responses can be read back.
    async fn socket_pair() -> (tokio::net::UdpSocket, tokio::net::UdpSocket, SocketAddr) {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        (server, client, client_addr)
    }

    /// Read one response, asserting it arrives.
    async fn recv(client: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("no response sent")
        .unwrap()
        .0;
        buf.truncate(n);
        buf
    }

    fn error_code(resp: &[u8]) -> (u8, u8) {
        assert_eq!(
            &resp[20..22],
            &[0x00, 0x09],
            "first attribute is ERROR-CODE"
        );
        (resp[26], resp[27])
    }

    fn assert_signed_with(resp: &[u8], key: &[u8; 16]) {
        let mi_start = resp.len() - 24;
        assert_eq!(
            &resp[mi_start..mi_start + 4],
            &[0x00, 0x08, 0x00, 0x14],
            "response ends in a MESSAGE-INTEGRITY attribute"
        );
        assert!(
            TurnAuth::verify_message_integrity(&resp[..mi_start], &resp[mi_start + 4..], key),
            "MESSAGE-INTEGRITY verifies"
        );
    }

    #[tokio::test]
    async fn refresh_without_allocation_returns_signed_437() {
        // Allocations live at most 60s, so a client that loses one Refresh gets
        // this 437 on its next one. Unsigned, an authenticated client discards
        // it (RFC 5389 §10.2.3) and retransmits for ~39.5s instead of
        // reallocating - which is why authentication runs before the lookup.
        let (h, _table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;

        let msg = sign(request(StunMethod::Refresh, 0x0004), &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();

        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x14], "Refresh error response");
        assert_eq!(error_code(&resp), (4, 37));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn channel_bind_forbidden_peer_returns_signed_403() {
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, USER.to_string(), 600);

        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![sa("127.0.0.1:1234")];
        let bind = sign(bind, &config, &key);
        h.handle_channel_bind(&bind, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 3));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn create_permission_forbidden_peer_returns_signed_403() {
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, USER.to_string(), 600);

        let mut perm = request(StunMethod::CreatePermission, 0x0008);
        perm.xor_peer_addresses = vec![sa("169.254.169.254:80")];
        let perm = sign(perm, &config, &key);
        h.handle_create_permission(&perm, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 3));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn request_for_another_users_allocation_is_rejected() {
        // RFC 5766 §10.1: post-Allocate requests carry the same credentials as
        // the Allocate did. Moving auth ahead of the lookup must not lose that.
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, "someone-else".to_string(), 600);

        let msg = sign(request(StunMethod::Refresh, 0x0004), &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 1), "401 Unauthorized");
    }

    // ---- Allocate over a lapsed allocation ----------------------------------

    #[tokio::test]
    async fn allocate_over_expired_allocation_starts_fresh() {
        // cleanup_expired runs every 2s, so a client that lets its allocation
        // lapse and reconnects usually finds the dead entry still in the table.
        // 437 there would lock it out of the port until the reaper catches up.
        let (h, table) = handler();
        let (server, client, client_addr) = socket_pair().await;

        // The coarse clock only moves when the server ticks it, so drive it by
        // hand: allocate with a zero lifetime, then step past the expiry.
        crate::coarse_time::init();
        let dead = table.create(client_addr, "u".to_string(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        crate::coarse_time::update_coarse_time();
        assert!(table.get(dead).unwrap().is_expired());

        let mut alloc = request(StunMethod::Allocate, 0x0003);
        alloc.requested_transport = Some(17);
        h.handle_allocate(&alloc, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x03], "Allocate success response");
        assert!(table.get(dead).is_none(), "the lapsed allocation is gone");
        let fresh = table.get_by_client(client_addr).expect("a new allocation");
        assert!(!fresh.is_expired());
    }

    #[tokio::test]
    async fn allocate_with_new_transaction_id_over_live_allocation_is_437() {
        let (h, table) = handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create_or_get(client_addr, "u".to_string(), 600, [1u8; 12]);

        let mut alloc = request(StunMethod::Allocate, 0x0003);
        alloc.requested_transport = Some(17);
        h.handle_allocate(&alloc, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 37));
    }

    // ---- Send indication ----------------------------------------------------

    #[tokio::test]
    async fn send_indication_without_target_does_not_arm_orphan_timer() {
        // Internal routing runs during ICE, before a peer exists. Arming the
        // orphan-sender timer here would have cleanup_orphaned_senders reap the
        // allocation of whoever joins the call first, 45s later, while it is
        // still actively sending and refreshing.
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40003");
        let id = table.create(client, "u".to_string(), 600);
        table.add_permission(id, ip(RELAY_IP));

        let mut send = request(StunMethod::Send, 0x0006);
        send.class = StunClass::Indication;
        send.xor_peer_addresses = vec![sa(&format!("{}:{}", RELAY_IP, RELAY_PORT))];
        // Not a STUN message, so the ICE-ufrag routing branch is skipped and the
        // broadcast fallback finds no unpaired target but the sender itself.
        send.data = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        h.handle_send(&send, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        // A zero timeout would report any armed timer as orphaned.
        assert!(!alloc.is_orphaned_sender(0));
    }

    #[test]
    fn private_networks_not_forbidden_by_default() {
        // Policy call: private ranges are common in legit on-prem/lab
        // deployments. is_forbidden_peer_ip intentionally allows them.
        assert!(!is_forbidden_peer_ip(ip("10.0.0.1")));
        assert!(!is_forbidden_peer_ip(ip("192.168.1.1")));
        assert!(!is_forbidden_peer_ip(ip("172.16.0.1")));
        // CGNAT and IPv6 ULA are likewise allowed by default.
        assert!(!is_forbidden_peer_ip(ip("100.64.0.1")));
        assert!(!is_forbidden_peer_ip(ip("fc00::1")));
    }
}
