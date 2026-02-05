//! Buffer pool for reducing per-packet memory allocations
//!
//! Provides reusable byte buffers to avoid heap allocation on every packet.

use parking_lot::Mutex;
use std::sync::Arc;

/// Maximum UDP packet size
const MAX_PACKET_SIZE: usize = 65535;

/// Default pool capacity (number of buffers to keep)
const DEFAULT_POOL_CAPACITY: usize = 256;

/// A reusable buffer from the pool
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Get a slice of the buffer up to the given length
    pub fn as_slice(&self, len: usize) -> &[u8] {
        &self.data[..len]
    }

    /// Get mutable access to the underlying buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the buffer capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool
        let mut buf = std::mem::take(&mut self.data);
        buf.clear();
        self.pool.return_buffer(buf);
    }
}

/// Pool of reusable byte buffers
pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    capacity: usize,
}

impl BufferPool {
    /// Create a new buffer pool with default capacity
    pub fn new() -> Arc<Self> {
        Self::with_capacity(DEFAULT_POOL_CAPACITY)
    }

    /// Create a new buffer pool with the given capacity
    pub fn with_capacity(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            buffers: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        })
    }

    /// Get a buffer from the pool, or allocate a new one if empty
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let mut data = self
            .buffers
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0; MAX_PACKET_SIZE]);
        // Ensure the buffer is full size for recv_from
        if data.len() < MAX_PACKET_SIZE {
            data.resize(MAX_PACKET_SIZE, 0);
        }
        PooledBuffer {
            data,
            pool: self.clone(),
        }
    }

    /// Return a buffer to the pool (called automatically on PooledBuffer drop)
    fn return_buffer(&self, buf: Vec<u8>) {
        let mut buffers = self.buffers.lock();
        if buffers.len() < self.capacity {
            buffers.push(buf);
        }
        // If at capacity, just drop the buffer
    }

    /// Pre-allocate buffers to avoid initial allocation spikes
    pub fn preallocate(self: &Arc<Self>, count: usize) {
        let mut buffers = self.buffers.lock();
        let to_add = count.min(self.capacity).saturating_sub(buffers.len());
        for _ in 0..to_add {
            buffers.push(vec![0; MAX_PACKET_SIZE]);
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(DEFAULT_POOL_CAPACITY)),
            capacity: DEFAULT_POOL_CAPACITY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new();

        // Get a buffer, write to it, drop it
        {
            let mut buf = pool.get();
            buf.as_mut_slice()[0] = 42;
        }

        // Get another buffer - should reuse
        let buf2 = pool.get();
        assert_eq!(buf2.capacity(), MAX_PACKET_SIZE);
    }

    #[test]
    fn test_buffer_pool_capacity_limit() {
        let pool = BufferPool::with_capacity(2);

        // Get 3 buffers
        let buf1 = pool.get();
        let buf2 = pool.get();
        let buf3 = pool.get();

        // Drop all - only 2 should be kept
        drop(buf1);
        drop(buf2);
        drop(buf3);

        assert_eq!(pool.buffers.lock().len(), 2);
    }

    #[test]
    fn test_preallocate() {
        let pool = BufferPool::with_capacity(10);
        pool.preallocate(5);

        assert_eq!(pool.buffers.lock().len(), 5);
    }
}
