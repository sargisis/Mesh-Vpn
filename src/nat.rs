//! NAT traversal helpers: UDP hole-punching probes.
//!
//! When two peers are both behind NAT, they each know the other's external
//! `ip:port` (reported by the coordinator's STUN-like mechanism).  To open
//! the NAT mapping both sides send a short burst of **probe packets** (type
//! `0x04`) to each other's external address.  The NAT sees outgoing traffic
//! and creates a mapping, so the subsequent Noise handshake can reach the
//! other side.
//!
//! Probe packets carry no payload and are silently discarded by the receiver
//! (they serve only to punch the hole).

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Packet type byte for a hole-punch probe.
pub const PROBE_PACKET_TYPE: u8 = 0x04;

/// Number of probe packets to send per hole-punch attempt.
const PROBE_COUNT: u32 = 3;

/// Delay between successive probe packets (ms).
const PROBE_INTERVAL_MS: u64 = 200;

/// Send a burst of empty probe packets with the configured `probe_byte` to `target`
/// to punch through NAT. Each probe is a single-byte packet.
///
/// This is fire-and-forget: errors on individual sends are logged but do not
/// abort the burst.
pub async fn punch_hole(sock: &Arc<UdpSocket>, target: SocketAddr, probe_byte: u8) {
    let probe = [probe_byte];
    for i in 0..PROBE_COUNT {
        match sock.send_to(&probe, target).await {
            Ok(_) => {
                tracing::debug!(
                    "Sent hole-punch probe {}/{} to {}",
                    i + 1,
                    PROBE_COUNT,
                    target
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to send hole-punch probe {}/{} to {}: {:?}",
                    i + 1,
                    PROBE_COUNT,
                    target,
                    e
                );
            }
        }
        if i + 1 < PROBE_COUNT {
            tokio::time::sleep(tokio::time::Duration::from_millis(PROBE_INTERVAL_MS)).await;
        }
    }
    tracing::info!("Hole-punch burst complete for {}", target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn punch_hole_sends_probes() {
        // Bind two sockets on loopback to verify the probes arrive.
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = receiver.local_addr().unwrap();

        punch_hole(&sender, target, PROBE_PACKET_TYPE).await;

        // All three probes should have arrived.
        let mut buf = [0u8; 16];
        for _ in 0..PROBE_COUNT {
            let (n, _addr) = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                receiver.recv_from(&mut buf),
            )
            .await
            .expect("probe should arrive within timeout")
            .unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], PROBE_PACKET_TYPE);
        }
    }

    #[test]
    fn probe_constants_are_sensible() {
        const { assert!(PROBE_COUNT >= 1, "must send at least one probe") };
        const { assert!(PROBE_INTERVAL_MS >= 50, "interval too small") };
    }
}
