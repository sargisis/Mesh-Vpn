use std::time::Instant;
use snow::StatelessTransportState;

/// Sliding-window anti-replay filter (RFC 6479 / WireGuard style).
///
/// Each session carries one of these on the RX side. A nonce is accepted at most
/// once: duplicates and nonces older than the window are rejected. The window only
/// advances on *authenticated* packets — `check_and_update` is called after the AEAD
/// verifies, so a forged packet can never poison the window and starve real traffic.
pub struct ReplayWindow {
    /// Bitmap over the last `WINDOW_BITS` nonces, indexed `nonce % WINDOW_BITS`.
    bitmap: [u64; Self::BITMAP_WORDS],
    /// Highest nonce accepted so far.
    last: u64,
    /// False until the first packet is accepted (so nonce 0 is valid).
    initialized: bool,
}

impl ReplayWindow {
    pub const WINDOW_BITS: u64 = 1024;
    pub const BITMAP_WORDS: usize = (Self::WINDOW_BITS / 64) as usize;

    pub fn new() -> Self {
        Self {
            bitmap: [0; Self::BITMAP_WORDS],
            last: 0,
            initialized: false,
        }
    }

    fn slot(nonce: u64) -> (usize, u64) {
        let bit = nonce % Self::WINDOW_BITS;
        ((bit / 64) as usize, bit % 64)
    }

    fn get_bit(&self, nonce: u64) -> bool {
        let (word, bit) = Self::slot(nonce);
        (self.bitmap[word] >> bit) & 1 == 1
    }

    fn set_bit(&mut self, nonce: u64) {
        let (word, bit) = Self::slot(nonce);
        self.bitmap[word] |= 1u64 << bit;
    }

    fn clear_bit(&mut self, nonce: u64) {
        let (word, bit) = Self::slot(nonce);
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Returns true if `nonce` has not been seen and is within the window, recording
    /// it as seen. Returns false for duplicates and for nonces too old to track.
    pub fn check_and_update(&mut self, nonce: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.last = nonce;
            self.set_bit(nonce);
            return true;
        }

        if nonce > self.last {
            // Newer than anything seen: advance the window, clearing the slots that
            // are newly exposed so stale bits from `WINDOW_BITS` ago don't linger.
            let shift = nonce - self.last;
            if shift >= Self::WINDOW_BITS {
                self.bitmap = [0; Self::BITMAP_WORDS];
            } else {
                for n in (self.last + 1)..=nonce {
                    self.clear_bit(n);
                }
            }
            self.last = nonce;
            self.set_bit(nonce);
            true
        } else {
            // Within or below the window.
            if self.last - nonce >= Self::WINDOW_BITS {
                return false; // too old to tell — reject
            }
            if self.get_bit(nonce) {
                return false; // already seen — replay
            }
            self.set_bit(nonce);
            true
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ActiveSession {
    pub state: StatelessTransportState,
    pub tx_nonce: u64,
    pub established_at: Instant,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub replay: ReplayWindow,
}
