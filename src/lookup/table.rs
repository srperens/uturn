//! Allocation lookup tables
//!
//! Multiple lookup paths for efficient packet routing:
//! - Source address (fast path for established flows)
//! - ICE username fragment (bi-directional matching)
//! - Peer tuple (IP:port)
//! - TURN channel ID

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::coarse_time::{coarse_now_ms, is_expired_secs};

/// Unique allocation identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(u64);

impl AllocationId {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for AllocationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "alloc-{}", self.0)
    }
}

/// TURN allocation state
#[derive(Debug)]
pub struct Allocation {
    pub id: AllocationId,

    /// Client's address (TURN control connection)
    pub client_addr: SocketAddr,

    /// Local ICE username fragment
    pub local_ufrag: String,

    /// Remote ICE username fragment (learned from binding requests)
    pub remote_ufrag: Option<String>,

    /// Permitted peer IP addresses
    pub permissions: RwLock<HashSet<IpAddr>>,

    /// Channel bindings: channel_id -> peer_addr
    pub channels: DashMap<u16, SocketAddr>,

    /// Reverse channel lookup: peer_addr -> channel_id
    pub channels_reverse: DashMap<SocketAddr, u16>,

    /// Known peer addresses (learned from traffic)
    pub known_peers: DashMap<SocketAddr, PeerInfo>,

    /// Allocation expiry time (milliseconds since coarse_time init)
    expires_at_ms: AtomicU64,

    /// Allocation lifetime in seconds (for refresh calculations)
    lifetime_secs: AtomicU64,

    /// Last activity time (coarse timestamp, milliseconds since init)
    last_activity_ms: AtomicU64,

    /// Last time we received traffic FROM the client (coarse timestamp)
    /// Used for inactivity detection (client gone but sender still active)
    last_received_ms: AtomicU64,

    /// Last time we successfully relayed data (coarse timestamp)
    /// Used to detect senders with no recipients. 0 = never tried.
    last_successful_relay_ms: AtomicU64,

    /// Whether we've ever attempted a relay (for orphan detection)
    has_relay_attempt: std::sync::atomic::AtomicBool,

    /// Username for authentication
    pub username: String,

    /// Transaction id of the Allocate request that created this allocation.
    /// Used to tell a retransmitted Allocate (same id: resend success) from a
    /// new Allocate over an existing 5-tuple (437 Allocation Mismatch).
    pub allocate_txn_id: [u8; 12],

    /// Remote ufrag this allocation wants to communicate with (from ICE)
    /// Set when we see a STUN Binding Request with USERNAME attribute
    pub paired_ufrag: RwLock<Option<String>>,

    /// This allocation's ICE ufrag (learned from STUN USERNAME attribute)
    /// Different from local_ufrag which is server-generated
    pub ice_ufrag: RwLock<Option<String>>,

    /// Remote ICE ufrag this allocation communicates with (from STUN USERNAME)
    pub ice_remote_ufrag: RwLock<Option<String>>,
}

/// Information about a known peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// When we last saw traffic from this peer (coarse timestamp in ms)
    pub last_seen_ms: u64,
}

impl Allocation {
    /// Create a new allocation
    pub fn new(
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
        allocate_txn_id: [u8; 12],
    ) -> Self {
        let now_ms = coarse_now_ms();
        let expires_ms = now_ms + (lifetime_secs as u64 * 1000);
        Self {
            id: AllocationId::new(),
            client_addr,
            local_ufrag: generate_ufrag(),
            remote_ufrag: None,
            permissions: RwLock::new(HashSet::new()),
            channels: DashMap::new(),
            channels_reverse: DashMap::new(),
            known_peers: DashMap::new(),
            expires_at_ms: AtomicU64::new(expires_ms),
            lifetime_secs: AtomicU64::new(lifetime_secs as u64),
            last_activity_ms: AtomicU64::new(now_ms),
            last_received_ms: AtomicU64::new(now_ms),
            last_successful_relay_ms: AtomicU64::new(0),
            has_relay_attempt: std::sync::atomic::AtomicBool::new(false),
            username,
            allocate_txn_id,
            paired_ufrag: RwLock::new(None),
            ice_ufrag: RwLock::new(None),
            ice_remote_ufrag: RwLock::new(None),
        }
    }

    /// Set the paired ufrag (from ICE USERNAME)
    /// Returns true if this is a new pairing
    pub fn set_paired_ufrag(&self, ufrag: String) -> bool {
        let mut guard = self.paired_ufrag.write();
        if guard.as_ref() == Some(&ufrag) {
            return false;
        }
        *guard = Some(ufrag);
        true
    }

    /// Get the paired ufrag
    pub fn get_paired_ufrag(&self) -> Option<String> {
        self.paired_ufrag.read().clone()
    }

    /// Set this allocation's ICE ufrag (from STUN USERNAME local part)
    /// Returns true if this is a new value
    pub fn set_ice_ufrag(&self, ufrag: String) -> bool {
        let mut guard = self.ice_ufrag.write();
        if guard.as_ref() == Some(&ufrag) {
            return false;
        }
        *guard = Some(ufrag);
        true
    }

    /// Get this allocation's ICE ufrag
    pub fn get_ice_ufrag(&self) -> Option<String> {
        self.ice_ufrag.read().clone()
    }

    /// Set the remote ICE ufrag (peer this allocation communicates with)
    pub fn set_ice_remote_ufrag(&self, ufrag: String) -> bool {
        let mut guard = self.ice_remote_ufrag.write();
        if guard.as_ref() == Some(&ufrag) {
            return false;
        }
        *guard = Some(ufrag);
        true
    }

    /// Get the remote ICE ufrag
    pub fn get_ice_remote_ufrag(&self) -> Option<String> {
        self.ice_remote_ufrag.read().clone()
    }

    /// Check if a peer IP is permitted
    #[inline]
    pub fn is_permitted(&self, peer_ip: IpAddr) -> bool {
        self.permissions.read().contains(&peer_ip)
    }

    /// Add a permission for a peer IP
    #[inline]
    pub fn add_permission(&self, peer_ip: IpAddr) {
        self.permissions.write().insert(peer_ip);
    }

    /// Number of permission entries currently held.
    #[inline]
    pub fn permissions_count(&self) -> usize {
        self.permissions.read().len()
    }

    /// Bind a channel to a peer address.
    ///
    /// Keeps `channels` and `channels_reverse` consistent: if the channel was
    /// previously bound to another peer, or the peer to another channel, the
    /// stale entries are removed. Otherwise traffic from the old peer would
    /// still be framed with a channel number the client now associates with
    /// the new peer. (The handler rejects such conflicting binds with 400 per
    /// RFC 5766 §11.2; this is defense-in-depth.)
    pub fn bind_channel(&self, channel: u16, peer_addr: SocketAddr) {
        if let Some(old_peer) = self.channels.insert(channel, peer_addr) {
            if old_peer != peer_addr {
                self.channels_reverse.remove(&old_peer);
            }
        }
        if let Some(old_channel) = self.channels_reverse.insert(peer_addr, channel) {
            if old_channel != channel {
                self.channels.remove(&old_channel);
            }
        }
    }

    /// Number of channels currently bound.
    #[inline]
    pub fn channels_count(&self) -> usize {
        self.channels.len()
    }

    /// Get channel for a peer address
    #[inline]
    pub fn channel_for_peer(&self, peer_addr: SocketAddr) -> Option<u16> {
        self.channels_reverse.get(&peer_addr).map(|r| *r)
    }

    /// Get peer address for a channel
    #[inline]
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.channels.get(&channel).map(|r| *r)
    }

    /// Update last activity time (lock-free, uses coarse timestamp)
    #[inline]
    pub fn touch(&self) {
        self.last_activity_ms
            .store(coarse_now_ms(), Ordering::Relaxed);
    }

    /// Update last received time (traffic FROM client)
    /// Call this only when receiving traffic FROM the client, not when sending TO them
    #[inline]
    pub fn touch_received(&self) {
        let now = coarse_now_ms();
        self.last_received_ms.store(now, Ordering::Relaxed);
        self.last_activity_ms.store(now, Ordering::Relaxed);
    }

    /// Check if client is inactive (no traffic FROM client for given duration)
    #[inline]
    pub fn is_inactive(&self, timeout_secs: u64) -> bool {
        is_expired_secs(self.last_received_ms.load(Ordering::Relaxed), timeout_secs)
    }

    /// Record a successful relay (data was sent to at least one target)
    #[inline]
    pub fn touch_relay_success(&self) {
        self.last_successful_relay_ms
            .store(coarse_now_ms(), Ordering::Relaxed);
        self.has_relay_attempt.store(true, Ordering::Relaxed);
    }

    /// Record a relay attempt - starts the orphan timer if not already started
    #[inline]
    pub fn touch_relay_attempt(&self) {
        // Only set if we haven't recorded any relay yet
        if !self.has_relay_attempt.swap(true, Ordering::Relaxed) {
            self.last_successful_relay_ms
                .store(coarse_now_ms(), Ordering::Relaxed);
        }
    }

    /// Check if sender is orphaned (sending but no targets for given duration)
    #[inline]
    pub fn is_orphaned_sender(&self, timeout_secs: u64) -> bool {
        if !self.has_relay_attempt.load(Ordering::Relaxed) {
            // Never tried to relay - not orphaned
            return false;
        }
        is_expired_secs(
            self.last_successful_relay_ms.load(Ordering::Relaxed),
            timeout_secs,
        )
    }

    /// Check if allocation has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        coarse_now_ms() > self.expires_at_ms.load(Ordering::Relaxed)
    }

    /// Refresh the allocation lifetime
    pub fn refresh(&self, lifetime_secs: u32) {
        let now_ms = coarse_now_ms();
        let expires_ms = now_ms + (lifetime_secs as u64 * 1000);
        self.expires_at_ms.store(expires_ms, Ordering::Relaxed);
        self.lifetime_secs
            .store(lifetime_secs as u64, Ordering::Relaxed);
    }

    /// Get remaining lifetime in seconds
    pub fn remaining_lifetime(&self) -> u32 {
        let expires_ms = self.expires_at_ms.load(Ordering::Relaxed);
        let now_ms = coarse_now_ms();
        if expires_ms > now_ms {
            ((expires_ms - now_ms) / 1000) as u32
        } else {
            0
        }
    }
}

/// ICE ufrag pair for bidirectional matching
/// Format: (local_ufrag, remote_ufrag)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IceUfragPair {
    local: String,
    remote: String,
}

impl IceUfragPair {
    fn new(local: String, remote: String) -> Self {
        Self { local, remote }
    }
}

/// Multi-index lookup table for allocations
///
/// LOCK ORDER (must hold globally to avoid ABBA deadlocks):
/// `allocations` is the primary map; every other field is a secondary index.
/// Any code that needs guards on both the primary map and a secondary index
/// MUST acquire the `allocations` guard FIRST. The `cleanup_*` paths rely on
/// this: they hold an `allocations` shard write lock (via `retain`) and then
/// mutate the secondary indices. A path that locked a secondary index first
/// and then `allocations` would deadlock against a concurrent cleanup on the
/// multi-thread runtime.
pub struct AllocationTable {
    /// All allocations by ID
    allocations: DashMap<AllocationId, Allocation>,

    /// Lookup by client address (primary key)
    by_client: DashMap<SocketAddr, AllocationId>,

    /// Lookup by local ufrag
    by_ufrag: DashMap<String, AllocationId>,

    /// Lookup by permitted peer IP -> list of allocations
    /// (multiple clients may permit the same peer)
    by_permission: DashMap<IpAddr, Vec<AllocationId>>,

    /// Lookup by (peer_ip, peer_port) for fast path
    by_peer_tuple: DashMap<SocketAddr, AllocationId>,

    /// Lookup by ICE ufrag (learned from STUN USERNAME attribute)
    /// This is the client's actual ICE ufrag, not server-generated
    by_ice_ufrag: DashMap<String, AllocationId>,

    /// Lookup by ICE ufrag pair for O(1) bidirectional matching
    /// Key: (local_ufrag, remote_ufrag) -> allocation that wants to receive from that pair
    by_ice_ufrag_pair: DashMap<IceUfragPair, AllocationId>,
}

impl AllocationTable {
    /// Create a new empty table
    pub fn new() -> Self {
        Self {
            allocations: DashMap::new(),
            by_client: DashMap::new(),
            by_ufrag: DashMap::new(),
            by_permission: DashMap::new(),
            by_peer_tuple: DashMap::new(),
            by_ice_ufrag: DashMap::new(),
            by_ice_ufrag_pair: DashMap::new(),
        }
    }

    /// Create a new allocation atomically, or return existing allocation ID
    ///
    /// This prevents race conditions where concurrent Allocate requests from
    /// the same client could create multiple allocations.
    ///
    /// Returns (allocation_id, created) where created is true if new, false if existing.
    pub fn create_or_get(
        &self,
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
        allocate_txn_id: [u8; 12],
    ) -> (AllocationId, bool) {
        use dashmap::mapref::entry::Entry;

        // Fast path: an allocation already exists. The guard is dropped at the
        // end of this statement, before any other map is touched.
        if let Some(id) = self.by_client.get(&client_addr).map(|r| *r) {
            return (id, false);
        }

        // Lock-order invariant: `allocations` before any secondary index, and
        // never hold guards on both at once. Insert into the primary map first
        // (guard released immediately), then claim the by_client slot. If we
        // lose the race for the slot, roll back our primary insert.
        let alloc = Allocation::new(client_addr, username, lifetime_secs, allocate_txn_id);
        let id = alloc.id;
        let ufrag = alloc.local_ufrag.clone();
        self.allocations.insert(id, alloc);

        let claimed = match self.by_client.entry(client_addr) {
            Entry::Occupied(entry) => Err(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(id);
                Ok(())
            }
        };

        match claimed {
            Ok(()) => {
                self.by_ufrag.insert(ufrag, id);
                (id, true)
            }
            Err(existing) => {
                // Concurrent request won the race - discard ours.
                self.allocations.remove(&id);
                (existing, false)
            }
        }
    }

    /// Create a new allocation (non-atomic, for backward compatibility)
    ///
    /// Prefer `create_or_get` for new code to avoid race conditions.
    pub fn create(
        &self,
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
    ) -> AllocationId {
        let (id, _created) = self.create_or_get(client_addr, username, lifetime_secs, [0u8; 12]);
        id
    }

    /// Get allocation by ID
    #[inline]
    pub fn get(
        &self,
        id: AllocationId,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        self.allocations.get(&id)
    }

    /// Get allocation by client address
    #[inline]
    pub fn get_by_client(
        &self,
        addr: SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        // Copy the id out so the by_client guard is released before we take
        // an `allocations` guard. Holding both inverts the documented lock
        // order (cleanup holds `allocations` then removes from `by_client`)
        // and can deadlock against a concurrent cleanup.
        let id = *self.by_client.get(&addr)?;
        self.allocations.get(&id)
    }

    /// Check if address is a known client (has an allocation)
    /// Use this to determine if traffic is from a client vs a peer
    #[inline]
    pub fn is_client(&self, addr: SocketAddr) -> bool {
        self.by_client.contains_key(&addr)
    }

    /// Lookup allocation ID by peer tuple (for relay traffic from peers)
    /// Returns the allocation that should receive traffic from this peer
    #[inline]
    pub fn lookup_by_peer_tuple(&self, addr: SocketAddr) -> Option<AllocationId> {
        self.by_peer_tuple.get(&addr).map(|r| *r)
    }

    /// Lookup allocation ID by source address (fast path for any traffic)
    /// Note: This returns an allocation ID but does NOT indicate if it's a client or peer.
    /// Use is_client() to determine traffic direction.
    pub fn lookup_by_source(&self, addr: SocketAddr) -> Option<AllocationId> {
        // First try client address (for TURN control traffic)
        if let Some(id) = self.by_client.get(&addr) {
            return Some(*id);
        }

        // Then try peer tuple (for relay traffic from peers)
        self.by_peer_tuple.get(&addr).map(|r| *r)
    }

    /// Lookup by ICE ufrag
    pub fn lookup_by_ufrag(&self, ufrag: &str) -> Option<AllocationId> {
        self.by_ufrag.get(ufrag).map(|r| *r)
    }

    /// Find all allocations that are paired with a given ufrag
    /// These are allocations that want to receive data from the allocation with that ufrag
    pub fn find_paired_allocations(&self, ufrag: &str) -> Vec<AllocationId> {
        let mut result = Vec::new();
        for entry in self.allocations.iter() {
            if let Some(paired) = entry.value().get_paired_ufrag() {
                if paired == ufrag {
                    result.push(entry.value().id);
                }
            }
        }
        result
    }

    /// Set pairing: receiver with ice_ufrag=receiver_ufrag should receive from sender_ufrag
    /// This is called when we see sender send STUN Binding Request to receiver
    /// Returns true if the pairing was set, false if receiver not found
    pub fn set_pairing(&self, sender_ice_ufrag: &str, receiver_ice_ufrag: &str) -> bool {
        // Find the receiver allocation by ICE ufrag
        if let Some(receiver_id) = self.lookup_by_ice_ufrag(receiver_ice_ufrag) {
            if let Some(receiver_alloc) = self.allocations.get(&receiver_id) {
                receiver_alloc.set_paired_ufrag(sender_ice_ufrag.to_string());
                return true;
            }
        }
        false
    }

    /// Register ICE ufrag pair for an allocation (learned from STUN USERNAME)
    /// local_ufrag is this client's ufrag, remote_ufrag is who they want to talk to
    ///
    /// Uses by_ice_ufrag as atomic check: if local_ufrag already registered to another
    /// allocation, this is a broadcast duplicate and we skip registration.
    pub fn register_ice_ufrags(
        &self,
        id: AllocationId,
        local_ufrag: String,
        remote_ufrag: String,
    ) -> bool {
        use dashmap::mapref::entry::Entry;

        // Lock-order invariant: `allocations` MUST be locked before any secondary
        // index, never the reverse. The cleanup paths (`cleanup_expired` /
        // `cleanup_inactive` / `cleanup_orphaned_senders`) hold an `allocations`
        // shard write lock via `retain` and then reach into `by_ice_ufrag`. If we
        // locked `by_ice_ufrag` first and then `allocations` here, a concurrent
        // cleanup on the multi-thread runtime would deadlock (ABBA). So acquire
        // the allocation ref first and hold it across the by_ice_ufrag claim.
        let alloc = match self.allocations.get(&id) {
            Some(a) => a,
            None => return false,
        };

        // Atomic check: try to claim local_ufrag in the by_ice_ufrag index.
        // If already present (this or another allocation), it's a broadcast
        // duplicate and we skip registration.
        match self.by_ice_ufrag.entry(local_ufrag.clone()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                if alloc.get_ice_ufrag().is_some() {
                    // Allocation already has a ufrag, don't overwrite
                    return false;
                }
                alloc.set_ice_ufrag(local_ufrag.clone());
                alloc.set_ice_remote_ufrag(remote_ufrag.clone());
                entry.insert(id);

                // Also register in the pair index for O(1) bidirectional lookup
                // Key is (local, remote) so find_ice_peers can lookup by reverse
                let pair = IceUfragPair::new(local_ufrag, remote_ufrag);
                self.by_ice_ufrag_pair.insert(pair, id);

                true
            }
        }
    }

    /// Lookup by ICE ufrag (client's actual ICE ufrag from STUN)
    pub fn lookup_by_ice_ufrag(&self, ice_ufrag: &str) -> Option<AllocationId> {
        self.by_ice_ufrag.get(ice_ufrag).map(|r| *r)
    }

    /// Find all allocations paired with a given ICE ufrag
    /// These are allocations that want to receive from sender with that ice_ufrag
    pub fn find_paired_by_ice_ufrag(&self, ice_ufrag: &str) -> Vec<AllocationId> {
        let mut result = Vec::new();
        for entry in self.allocations.iter() {
            if let Some(paired) = entry.value().get_paired_ufrag() {
                if paired == ice_ufrag {
                    result.push(entry.value().id);
                }
            }
        }
        result
    }

    /// Find allocations that are ICE peers of the sender
    /// Uses bi-directional matching: if sender has (local=X, remote=Y),
    /// find allocations with (local=Y, remote=X)
    ///
    /// This is now O(1) using the by_ice_ufrag_pair index instead of O(n) iteration.
    pub fn find_ice_peers(&self, sender_local: &str, sender_remote: &str) -> Vec<AllocationId> {
        // We want to find allocations where:
        // - their local_ufrag == sender's remote_ufrag
        // - their remote_ufrag == sender's local_ufrag
        // So we look up the "reverse" pair
        let reverse_pair = IceUfragPair::new(sender_remote.to_string(), sender_local.to_string());

        if let Some(id) = self.by_ice_ufrag_pair.get(&reverse_pair) {
            vec![*id]
        } else {
            Vec::new()
        }
    }

    /// Lookup by peer IP (may return multiple allocations)
    #[inline]
    pub fn lookup_by_peer_ip(&self, ip: IpAddr) -> Vec<AllocationId> {
        self.by_permission
            .get(&ip)
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Lookup by peer address - prefer tuple, fallback to IP
    ///
    /// Returns (candidates, is_unique) where:
    /// - candidates: list of allocation IDs that may receive this traffic
    /// - is_unique: true if exactly one candidate (safe to register tuple)
    ///
    /// This function enables fast-path routing: on first packet from a peer,
    /// if is_unique is true, the caller should register the tuple for future
    /// direct lookups. This avoids bandwidth multiplication when multiple
    /// allocations share the same peer IP permission.
    #[inline]
    pub fn lookup_by_peer_addr(&self, addr: SocketAddr) -> (Vec<AllocationId>, bool) {
        // Fast path: direct tuple lookup (already registered)
        if let Some(id) = self.by_peer_tuple.get(&addr) {
            return (vec![*id], true);
        }

        // Slow path: IP-based lookup (first packet from this peer)
        let candidates = self.lookup_by_peer_ip(addr.ip());
        let is_unique = candidates.len() == 1;
        (candidates, is_unique)
    }

    /// Add permission and update index
    pub fn add_permission(&self, id: AllocationId, peer_ip: IpAddr) {
        if let Some(alloc) = self.allocations.get(&id) {
            alloc.add_permission(peer_ip);
        }

        // Only add if not already in the list (avoid duplicates on permission refresh)
        let mut entry = self.by_permission.entry(peer_ip).or_default();
        if !entry.contains(&id) {
            entry.push(id);
        }
    }

    /// Atomically check the permission cap and insert new peer IPs.
    ///
    /// Holds the allocation's permissions write lock across the count check
    /// and insert, preventing TOCTOU races between concurrent CreatePermission
    /// requests. Returns `false` if the allocation does not exist or if adding
    /// the new IPs would exceed `cap`; in both cases no state is modified.
    pub fn try_add_permissions_capped(
        &self,
        id: AllocationId,
        peer_ips: &[IpAddr],
        cap: usize,
    ) -> bool {
        let alloc = match self.allocations.get(&id) {
            Some(a) => a,
            None => return false,
        };

        let to_add: Vec<IpAddr> = {
            let mut perms = alloc.permissions.write();
            let new_ips: Vec<IpAddr> = peer_ips
                .iter()
                .filter(|ip| !perms.contains(*ip))
                .copied()
                .collect();
            if perms.len() + new_ips.len() > cap {
                return false;
            }
            for ip in &new_ips {
                perms.insert(*ip);
            }
            new_ips
        };

        // Update reverse index outside the per-allocation lock.
        for ip in to_add {
            let mut entry = self.by_permission.entry(ip).or_default();
            if !entry.contains(&id) {
                entry.push(id);
            }
        }

        true
    }

    /// Register peer tuple for fast path lookup
    /// Also records in known_peers so it gets cleaned up with the allocation
    pub fn register_peer_tuple(&self, id: AllocationId, peer_addr: SocketAddr) {
        self.by_peer_tuple.insert(peer_addr, id);

        // Also record in known_peers so cleanup removes the by_peer_tuple entry
        if let Some(alloc) = self.allocations.get(&id) {
            alloc
                .known_peers
                .entry(peer_addr)
                .or_insert_with(|| PeerInfo {
                    last_seen_ms: coarse_now_ms(),
                });
        }
    }

    /// Remove an allocation.
    ///
    /// Returns `true` if the allocation existed and was removed by this call,
    /// `false` if it was already gone (e.g. reaped concurrently by cleanup).
    /// Callers that account for the removal elsewhere (rate limiter quota)
    /// must only do so when this returns `true`.
    pub fn remove(&self, id: AllocationId) -> bool {
        if let Some((_, alloc)) = self.allocations.remove(&id) {
            self.by_client.remove(&alloc.client_addr);
            self.by_ufrag.remove(&alloc.local_ufrag);

            // Remove from ICE ufrag indices
            if let (Some(ice_ufrag), Some(ice_remote)) =
                (alloc.get_ice_ufrag(), alloc.get_ice_remote_ufrag())
            {
                self.by_ice_ufrag.remove(&ice_ufrag);
                let pair = IceUfragPair::new(ice_ufrag, ice_remote);
                self.by_ice_ufrag_pair.remove(&pair);
            } else if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                self.by_ice_ufrag.remove(&ice_ufrag);
            }

            for peer_ip in alloc.permissions.read().iter() {
                if let Some(mut ids) = self.by_permission.get_mut(peer_ip) {
                    ids.retain(|&i| i != id);
                }
            }

            for entry in alloc.known_peers.iter() {
                self.by_peer_tuple.remove(entry.key());
            }
            true
        } else {
            false
        }
    }

    /// Remove expired allocations (atomic per-entry removal)
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_expired(&self) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_expired() {
                tracing::info!(
                    "Removing expired allocation {} for {} (lifetime ended)",
                    id,
                    alloc.client_addr
                );
                // Clean up indices before removal
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                self.by_ufrag.remove(&alloc.local_ufrag);
                // Clean up ICE ufrag indices
                if let (Some(ice_ufrag), Some(ice_remote)) =
                    (alloc.get_ice_ufrag(), alloc.get_ice_remote_ufrag())
                {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                    let pair = IceUfragPair::new(ice_ufrag, ice_remote);
                    self.by_ice_ufrag_pair.remove(&pair);
                } else if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                }
                for peer_ip in alloc.permissions.read().iter() {
                    if let Some(mut ids) = self.by_permission.get_mut(peer_ip) {
                        ids.retain(|&i| i != *id);
                    }
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });
        removed_ips
    }

    /// Remove inactive allocations (no traffic FROM client for timeout_secs)
    /// Uses atomic per-entry removal to avoid race conditions
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_inactive(&self, timeout_secs: u64) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_inactive(timeout_secs) {
                tracing::info!(
                    "Removing inactive allocation {} for {} (no traffic for {}s)",
                    id,
                    alloc.client_addr,
                    timeout_secs
                );
                // Clean up indices
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                self.by_ufrag.remove(&alloc.local_ufrag);
                // Clean up ICE ufrag indices
                if let (Some(ice_ufrag), Some(ice_remote)) =
                    (alloc.get_ice_ufrag(), alloc.get_ice_remote_ufrag())
                {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                    let pair = IceUfragPair::new(ice_ufrag, ice_remote);
                    self.by_ice_ufrag_pair.remove(&pair);
                } else if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                }
                for peer_ip in alloc.permissions.read().iter() {
                    if let Some(mut ids) = self.by_permission.get_mut(peer_ip) {
                        ids.retain(|&i| i != *id);
                    }
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false
            } else {
                true
            }
        });
        removed_ips
    }

    /// Remove orphaned sender allocations (sending but no targets for timeout_secs)
    /// Uses atomic per-entry removal to avoid race conditions
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_orphaned_senders(&self, timeout_secs: u64) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_orphaned_sender(timeout_secs) {
                tracing::info!(
                    "Removing orphaned sender {} for {} (no relay targets for {}s)",
                    id,
                    alloc.client_addr,
                    timeout_secs
                );
                // Clean up indices
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                self.by_ufrag.remove(&alloc.local_ufrag);
                // Clean up ICE ufrag indices
                if let (Some(ice_ufrag), Some(ice_remote)) =
                    (alloc.get_ice_ufrag(), alloc.get_ice_remote_ufrag())
                {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                    let pair = IceUfragPair::new(ice_ufrag, ice_remote);
                    self.by_ice_ufrag_pair.remove(&pair);
                } else if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(&ice_ufrag);
                }
                for peer_ip in alloc.permissions.read().iter() {
                    if let Some(mut ids) = self.by_permission.get_mut(peer_ip) {
                        ids.retain(|&i| i != *id);
                    }
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false
            } else {
                true
            }
        });
        removed_ips
    }
}

impl Default for AllocationTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a cryptographically secure ICE username fragment
fn generate_ufrag() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.gen();
    // Base64-like encoding using alphanumeric chars (ICE-safe)
    bytes
        .iter()
        .map(|b| {
            let idx = (b % 62) as usize;
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            CHARS[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_create_allocation() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();

        let id = table.create(client, "testuser".to_string(), 600);

        assert!(table.get(id).is_some());
        assert!(table.get_by_client(client).is_some());
    }

    #[test]
    fn test_permission_lookup() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let id = table.create(client, "testuser".to_string(), 600);
        table.add_permission(id, peer_ip);

        let found = table.lookup_by_peer_ip(peer_ip);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], id);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn try_add_permissions_capped_rejects_when_over_cap() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        let peers = [ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")];
        // Cap of 2 with 3 new IPs -> reject, no state modification.
        assert!(!table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 0);
        for p in &peers {
            assert!(table.lookup_by_peer_ip(*p).is_empty());
        }
    }

    #[test]
    fn try_add_permissions_capped_allows_refresh_at_cap() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        let peers = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert!(table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);

        // Refresh the same IPs -- must not count as new additions.
        assert!(table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
    }

    #[test]
    fn try_add_permissions_capped_mixed_new_and_existing() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        assert!(table.try_add_permissions_capped(id, &[ip("10.0.0.1")], 2));
        // Existing 10.0.0.1 plus new 10.0.0.2 -> total 2, within cap of 2.
        assert!(table.try_add_permissions_capped(id, &[ip("10.0.0.1"), ip("10.0.0.2")], 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
        // Adding a third distinct IP now exceeds cap.
        assert!(!table.try_add_permissions_capped(id, &[ip("10.0.0.3")], 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
    }

    #[test]
    fn try_add_permissions_capped_is_atomic_under_concurrent_callers() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(AllocationTable::new());
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        const CAP: usize = 64;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 16;

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let table = table.clone();
                thread::spawn(move || {
                    let peers: Vec<IpAddr> = (0..PER_THREAD)
                        .map(|i| ip(&format!("10.{}.{}.1", t, i)))
                        .collect();
                    // Each thread tries to add 16 unique IPs. 8*16 = 128 > cap 64,
                    // so some must fail. The cap must never be exceeded regardless.
                    let _ = table.try_add_permissions_capped(id, &peers, CAP);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let total = table.get(id).unwrap().permissions_count();
        assert!(
            total <= CAP,
            "permissions_count {} exceeded cap {}",
            total,
            CAP
        );
    }

    /// Regression guard for the ABBA deadlock between `get_by_client` /
    /// `create_or_get` (previously: `by_client` guard held while locking
    /// `allocations`) and the `cleanup_*` paths (`allocations` retain lock held
    /// while removing from `by_client`). Same watchdog shape as the test below.
    #[test]
    fn client_lookup_and_cleanup_do_not_deadlock_under_contention() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let table = Arc::new(AllocationTable::new());
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        const WRITERS: usize = 8;
        for t in 0..WRITERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            let progress = Arc::clone(&progress);
            handles.push(thread::spawn(move || {
                let mut n: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    // Tiny port space so both maps collide on shards constantly.
                    let port = 30000 + ((t as u64 * 131 + n) % 64) as u16;
                    let client: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
                    let (id, _) = table.create_or_get(client, "u".to_string(), 600, [0u8; 12]);
                    if let Some(a) = table.get_by_client(client) {
                        assert_eq!(a.client_addr, client);
                    }
                    let _ = table.is_client(client);
                    let _ = table.get(id);
                    n += 1;
                }
                progress.fetch_add(n, Ordering::Relaxed);
            }));
        }

        const CLEANERS: usize = 2;
        for _ in 0..CLEANERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    table.cleanup_inactive(0);
                }
            }));
        }

        thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                let _ = h.join();
            }
            let _ = tx.send(());
        });

        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(()) => assert!(
                progress.load(Ordering::Relaxed) > 0,
                "writers made no progress"
            ),
            Err(_) => panic!(
                "deadlock: get_by_client/create_or_get and cleanup_* threads did not \
                 finish after stop -- a by_client guard is being held while locking \
                 allocations (see AllocationTable lock-order doc)"
            ),
        }
    }

    #[test]
    fn bind_channel_removes_stale_reverse_and_forward_entries() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        let a: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:5000".parse().unwrap();
        let alloc = table.get(id).unwrap();

        // Rebind the channel to another peer: the old peer must no longer map
        // to the channel.
        alloc.bind_channel(0x4000, a);
        alloc.bind_channel(0x4000, b);
        assert_eq!(alloc.peer_for_channel(0x4000), Some(b));
        assert_eq!(alloc.channel_for_peer(a), None);
        assert_eq!(alloc.channel_for_peer(b), Some(0x4000));
        assert_eq!(alloc.channels_count(), 1);

        // Rebind the peer to another channel: the old channel must be freed.
        alloc.bind_channel(0x4001, b);
        assert_eq!(alloc.peer_for_channel(0x4000), None);
        assert_eq!(alloc.peer_for_channel(0x4001), Some(b));
        assert_eq!(alloc.channel_for_peer(b), Some(0x4001));
        assert_eq!(alloc.channels_count(), 1);

        // Refreshing an identical binding is a no-op.
        alloc.bind_channel(0x4001, b);
        assert_eq!(alloc.channels_count(), 1);
    }

    #[test]
    fn remove_reports_whether_it_removed() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        assert!(table.remove(id));
        assert!(!table.remove(id));
        assert!(table.get_by_client(client).is_none());
    }

    /// Regression guard for the ABBA deadlock between `register_ice_ufrags`
    /// (locks `by_ice_ufrag` then `allocations`) and the `cleanup_*` paths
    /// (lock `allocations` via `retain`, then `by_ice_ufrag`). The lock-order
    /// invariant requires `allocations` to be acquired first everywhere. If a
    /// future change reintroduces the inverse order, the writer and cleanup
    /// threads deadlock and never observe `stop`, so the watchdog fails the test
    /// instead of hanging the whole suite.
    #[test]
    fn register_and_cleanup_do_not_deadlock_under_contention() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let table = Arc::new(AllocationTable::new());
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        // Writers: create an allocation and register a fresh ICE ufrag. The
        // fresh ufrag forces the `Vacant` arm of `register_ice_ufrags`, which is
        // where it holds a `by_ice_ufrag` write lock while touching `allocations`.
        const WRITERS: usize = 8;
        for t in 0..WRITERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            let progress = Arc::clone(&progress);
            handles.push(thread::spawn(move || {
                let mut n: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    // Small, recycled client-port space so shards collide often.
                    let port = 20000 + ((t as u64 * 251 + n) % 512) as u16;
                    let client: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
                    let id = table.create(client, "strom".to_string(), 600);
                    table.register_ice_ufrags(id, format!("L{}-{}", t, n), format!("R{}-{}", t, n));
                    n += 1;
                }
                progress.fetch_add(n, Ordering::Relaxed);
            }));
        }

        // Cleaners: `cleanup_inactive(0)` removes every allocation unconditionally
        // (now - last_received >= 0 always holds), exercising the removal branch
        // that locks `by_ice_ufrag` while holding the `allocations` retain lock.
        const CLEANERS: usize = 2;
        for _ in 0..CLEANERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    table.cleanup_inactive(0);
                }
            }));
        }

        thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);

        // Watchdog: a separate thread joins the workers. If they deadlocked they
        // never exit, the join blocks, and `recv_timeout` fails the test loudly.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                let _ = h.join();
            }
            let _ = tx.send(());
        });

        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(()) => assert!(
                progress.load(Ordering::Relaxed) > 0,
                "writers made no progress"
            ),
            Err(_) => panic!(
                "deadlock: register_ice_ufrags and cleanup_* threads did not finish \
                 after stop -- lock-order inversion reintroduced (allocations must be \
                 locked before any secondary index; see AllocationTable lock-order doc)"
            ),
        }
    }
}
