//! Allocation lookup tables
//!
//! Multiple lookup paths for efficient packet routing:
//! - Source address (fast path for established flows)
//! - ICE username fragment
//! - SSRC
//! - TURN channel ID

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::RwLock;

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

    /// Known SSRCs associated with this allocation
    pub ssrcs: RwLock<HashSet<u32>>,

    /// Known peer addresses (learned from traffic)
    pub known_peers: DashMap<SocketAddr, PeerInfo>,

    /// Allocation expiry time
    pub expires_at: RwLock<Instant>,

    /// Last activity time (any direction)
    pub last_activity: RwLock<Instant>,

    /// Last time we received traffic FROM the client
    /// Used for inactivity detection (client gone but sender still active)
    pub last_received: RwLock<Instant>,

    /// Last time we successfully relayed data to at least one target
    /// Used to detect senders with no recipients
    pub last_successful_relay: RwLock<Option<Instant>>,

    /// Username for authentication
    pub username: String,
}

/// Information about a known peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// When we last saw traffic from this peer
    pub last_seen: Instant,

    /// SSRCs observed from this peer
    pub ssrcs: HashSet<u32>,
}

impl Allocation {
    /// Create a new allocation
    pub fn new(client_addr: SocketAddr, username: String, lifetime_secs: u32) -> Self {
        let now = Instant::now();
        Self {
            id: AllocationId::new(),
            client_addr,
            local_ufrag: generate_ufrag(),
            remote_ufrag: None,
            permissions: RwLock::new(HashSet::new()),
            channels: DashMap::new(),
            channels_reverse: DashMap::new(),
            ssrcs: RwLock::new(HashSet::new()),
            known_peers: DashMap::new(),
            expires_at: RwLock::new(now + std::time::Duration::from_secs(lifetime_secs as u64)),
            last_activity: RwLock::new(now),
            last_received: RwLock::new(now),
            last_successful_relay: RwLock::new(None),
            username,
        }
    }

    /// Check if a peer IP is permitted
    pub fn is_permitted(&self, peer_ip: IpAddr) -> bool {
        self.permissions.read().contains(&peer_ip)
    }

    /// Add a permission for a peer IP
    pub fn add_permission(&self, peer_ip: IpAddr) {
        self.permissions.write().insert(peer_ip);
    }

    /// Bind a channel to a peer address
    pub fn bind_channel(&self, channel: u16, peer_addr: SocketAddr) {
        self.channels.insert(channel, peer_addr);
        self.channels_reverse.insert(peer_addr, channel);
    }

    /// Get channel for a peer address
    pub fn channel_for_peer(&self, peer_addr: SocketAddr) -> Option<u16> {
        self.channels_reverse.get(&peer_addr).map(|r| *r)
    }

    /// Get peer address for a channel
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.channels.get(&channel).map(|r| *r)
    }

    /// Maximum SSRCs to track per allocation (prevents memory DoS)
    const MAX_SSRCS_PER_ALLOCATION: usize = 100;

    /// Register an SSRC with this allocation
    ///
    /// If the limit is reached, oldest SSRCs are not tracked (we just ignore new ones)
    /// Returns true if the SSRC was newly registered, false if already known or limit reached
    pub fn register_ssrc(&self, ssrc: u32) -> bool {
        let mut ssrcs = self.ssrcs.write();
        if ssrcs.contains(&ssrc) {
            return false; // Already known
        }
        if ssrcs.len() >= Self::MAX_SSRCS_PER_ALLOCATION {
            return false; // Limit reached, don't track more
        }
        ssrcs.insert(ssrc);
        true
    }

    /// Update last activity time
    pub fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }

    /// Update last received time (traffic FROM client)
    /// Call this only when receiving traffic FROM the client, not when sending TO them
    pub fn touch_received(&self) {
        let now = Instant::now();
        *self.last_received.write() = now;
        *self.last_activity.write() = now;
    }

    /// Check if client is inactive (no traffic FROM client for given duration)
    pub fn is_inactive(&self, timeout_secs: u64) -> bool {
        let last = *self.last_received.read();
        Instant::now().duration_since(last).as_secs() >= timeout_secs
    }

    /// Record a successful relay (data was sent to at least one target)
    pub fn touch_relay_success(&self) {
        *self.last_successful_relay.write() = Some(Instant::now());
    }

    /// Record a relay attempt - starts the orphan timer if not already started
    pub fn touch_relay_attempt(&self) {
        let mut guard = self.last_successful_relay.write();
        if guard.is_none() {
            // First relay attempt with no prior success - start the timer
            *guard = Some(Instant::now());
        }
    }

    /// Check if sender is orphaned (sending but no targets for given duration)
    pub fn is_orphaned_sender(&self, timeout_secs: u64) -> bool {
        match *self.last_successful_relay.read() {
            Some(relay_time) => {
                // Check if last successful relay (or first attempt) was too long ago
                Instant::now().duration_since(relay_time).as_secs() >= timeout_secs
            }
            None => {
                // Never tried to relay - not orphaned (just a receiver or new allocation)
                false
            }
        }
    }

    /// Check if allocation has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > *self.expires_at.read()
    }

    /// Refresh the allocation lifetime
    pub fn refresh(&self, lifetime_secs: u32) {
        *self.expires_at.write() =
            Instant::now() + std::time::Duration::from_secs(lifetime_secs as u64);
    }

    /// Get remaining lifetime in seconds
    pub fn remaining_lifetime(&self) -> u32 {
        let expires = *self.expires_at.read();
        let now = Instant::now();
        if expires > now {
            (expires - now).as_secs() as u32
        } else {
            0
        }
    }
}

/// Multi-index lookup table for allocations
pub struct AllocationTable {
    /// All allocations by ID
    allocations: DashMap<AllocationId, Allocation>,

    /// Lookup by client address (primary key)
    by_client: DashMap<SocketAddr, AllocationId>,

    /// Lookup by local ufrag
    by_ufrag: DashMap<String, AllocationId>,

    /// Lookup by SSRC (may have multiple allocations per SSRC in rare cases)
    by_ssrc: DashMap<u32, AllocationId>,

    /// Lookup by permitted peer IP -> list of allocations
    /// (multiple clients may permit the same peer)
    by_permission: DashMap<IpAddr, Vec<AllocationId>>,

    /// Lookup by (peer_ip, peer_port) for fast path
    by_peer_tuple: DashMap<SocketAddr, AllocationId>,
}

impl AllocationTable {
    /// Create a new empty table
    pub fn new() -> Self {
        Self {
            allocations: DashMap::new(),
            by_client: DashMap::new(),
            by_ufrag: DashMap::new(),
            by_ssrc: DashMap::new(),
            by_permission: DashMap::new(),
            by_peer_tuple: DashMap::new(),
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
    ) -> (AllocationId, bool) {
        use dashmap::mapref::entry::Entry;

        // Use entry API for atomic check-and-insert
        match self.by_client.entry(client_addr) {
            Entry::Occupied(entry) => {
                // Allocation already exists for this client
                (*entry.get(), false)
            }
            Entry::Vacant(entry) => {
                // No allocation exists - create one atomically
                let alloc = Allocation::new(client_addr, username, lifetime_secs);
                let id = alloc.id;
                let ufrag = alloc.local_ufrag.clone();

                entry.insert(id);
                self.by_ufrag.insert(ufrag, id);
                self.allocations.insert(id, alloc);

                (id, true)
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
        let (id, _created) = self.create_or_get(client_addr, username, lifetime_secs);
        id
    }

    /// Get allocation by ID
    pub fn get(
        &self,
        id: AllocationId,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        self.allocations.get(&id)
    }

    /// Get allocation by client address
    pub fn get_by_client(
        &self,
        addr: SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        let id = self.by_client.get(&addr)?;
        self.allocations.get(&*id)
    }

    /// Check if address is a known client (has an allocation)
    /// Use this to determine if traffic is from a client vs a peer
    pub fn is_client(&self, addr: SocketAddr) -> bool {
        self.by_client.contains_key(&addr)
    }

    /// Lookup allocation ID by peer tuple (for relay traffic from peers)
    /// Returns the allocation that should receive traffic from this peer
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

    /// Lookup by SSRC
    pub fn lookup_by_ssrc(&self, ssrc: u32) -> Option<AllocationId> {
        self.by_ssrc.get(&ssrc).map(|r| *r)
    }

    /// Lookup by peer IP (may return multiple allocations)
    pub fn lookup_by_peer_ip(&self, ip: IpAddr) -> Vec<AllocationId> {
        self.by_permission
            .get(&ip)
            .map(|r| r.clone())
            .unwrap_or_default()
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

    /// Register SSRC and update index
    ///
    /// Only adds to global index if the allocation accepts the SSRC (hasn't hit limit)
    pub fn register_ssrc(&self, id: AllocationId, ssrc: u32) {
        if let Some(alloc) = self.allocations.get(&id) {
            if alloc.register_ssrc(ssrc) {
                // Only add to global index if allocation accepted it
                self.by_ssrc.insert(ssrc, id);
            }
        }
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
                    last_seen: Instant::now(),
                    ssrcs: HashSet::new(),
                });
        }
    }

    /// Remove an allocation
    pub fn remove(&self, id: AllocationId) {
        if let Some((_, alloc)) = self.allocations.remove(&id) {
            self.by_client.remove(&alloc.client_addr);
            self.by_ufrag.remove(&alloc.local_ufrag);

            for ssrc in alloc.ssrcs.read().iter() {
                self.by_ssrc.remove(ssrc);
            }

            for peer_ip in alloc.permissions.read().iter() {
                if let Some(mut ids) = self.by_permission.get_mut(peer_ip) {
                    ids.retain(|&i| i != id);
                }
            }

            for entry in alloc.known_peers.iter() {
                self.by_peer_tuple.remove(entry.key());
            }
        }
    }

    /// Remove expired allocations (atomic per-entry removal)
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_expired(&self) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_expired() {
                // Clean up indices before removal
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                self.by_ufrag.remove(&alloc.local_ufrag);
                for ssrc in alloc.ssrcs.read().iter() {
                    self.by_ssrc.remove(ssrc);
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
                for ssrc in alloc.ssrcs.read().iter() {
                    self.by_ssrc.remove(ssrc);
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
                for ssrc in alloc.ssrcs.read().iter() {
                    self.by_ssrc.remove(ssrc);
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

    #[test]
    fn test_ssrc_lookup() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();

        let id = table.create(client, "testuser".to_string(), 600);
        table.register_ssrc(id, 0x12345678);

        assert_eq!(table.lookup_by_ssrc(0x12345678), Some(id));
    }
}
