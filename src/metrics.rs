use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    pub total_rx_bytes: AtomicU64,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_packets: AtomicU64,
    pub total_tx_packets: AtomicU64,
    pub handshake_attempts: AtomicU64,
    pub handshake_successes: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            total_rx_bytes: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_packets: AtomicU64::new(0),
            total_tx_packets: AtomicU64::new(0),
            handshake_attempts: AtomicU64::new(0),
            handshake_successes: AtomicU64::new(0),
        }
    }

    pub fn add_rx(&self, bytes: u64) {
        self.total_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.total_rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_tx(&self, bytes: u64) {
        self.total_tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.total_tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake_attempt(&self) {
        self.handshake_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake_success(&self) {
        self.handshake_successes.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
