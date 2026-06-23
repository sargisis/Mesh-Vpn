//! TCP relay client for symmetric-NAT fallback (DERP-like).
//!
//! When direct UDP connectivity between two peers fails (e.g. both are behind
//! symmetric NAT), encrypted data packets are forwarded through a relay server
//! co-located with the coordinator.
//!
//! # Wire format
//!
//! The relay uses length-prefixed framing over TCP:
//!
//! ```text
//! ┌──────────┬────────────────┬──────────────────────┐
//! │ len (4B) │ dest_key (32B) │ encrypted payload    │
//! └──────────┴────────────────┴──────────────────────┘
//! ```
//!
//! - `len` is a big-endian u32 covering `dest_key + payload`.
//! - `dest_key` is the 32-byte Noise public key of the intended recipient.
//! - The payload is an already-encrypted AraxMesh packet (type byte + nonce +
//!   ciphertext) and is forwarded verbatim — the relay never sees plaintext.
//!
//! On connect the client sends a **32-byte identity frame** containing its own
//! Noise public key so the relay can route inbound traffic to it.
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A relayed packet received from the relay server (already decrypted by the
/// Noise layer on the peer that sent it through the relay).
#[derive(Debug)]
pub struct RelayedPacket {
    /// The Noise public key of the peer that sent this packet.
    pub from_key: [u8; 32],
    /// The encrypted AraxMesh payload (type + nonce + ciphertext).
    pub payload: Vec<u8>,
}

/// A packet to send through the relay.
#[derive(Debug)]
pub struct OutboundRelayPacket {
    /// The Noise public key of the intended recipient.
    pub dest_key: [u8; 32],
    /// The encrypted AraxMesh payload to forward.
    pub payload: Vec<u8>,
}

/// Manages a TCP connection to the relay server.
///
/// The client identifies itself on connect, then runs two loops:
/// - **TX**: reads from `outbound_rx` and writes length-prefixed frames.
/// - **RX**: reads length-prefixed frames and sends them to `inbound_tx`.
pub struct RelayClient {
    relay_addr: String,
    local_pubkey: [u8; 32],
}

impl RelayClient {
    pub fn new(relay_addr: String, local_pubkey: [u8; 32]) -> Self {
        Self {
            relay_addr,
            local_pubkey,
        }
    }

    /// Connect to the relay, identify, and split into TX/RX halves.
    ///
    /// Returns channels for sending and receiving relayed packets.
    /// The returned join handle runs until the TCP connection drops.
    pub async fn connect(
        &self,
    ) -> Result<
        (
            mpsc::Sender<OutboundRelayPacket>,
            mpsc::Receiver<RelayedPacket>,
            tokio::task::JoinHandle<()>,
        ),
        std::io::Error,
    > {
        let stream = TcpStream::connect(&self.relay_addr).await?;
        stream.set_nodelay(true)?;
        let (mut read_half, mut write_half) = stream.into_split();

        // Send 32-byte identity frame.
        write_half.write_all(&self.local_pubkey).await?;

        tracing::info!(
            "Connected to relay at {} as {}",
            self.relay_addr,
            hex::encode(self.local_pubkey)
        );

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundRelayPacket>(64);
        let (inbound_tx, inbound_rx) = mpsc::channel::<RelayedPacket>(64);

        let handle = tokio::spawn(async move {
            let tx_task = async {
                while let Some(pkt) = outbound_rx.recv().await {
                    let frame_len = (32 + pkt.payload.len()) as u32;
                    if let Err(e) = write_half.write_all(&frame_len.to_be_bytes()).await {
                        tracing::warn!("Relay TX error (len): {:?}", e);
                        break;
                    }
                    if let Err(e) = write_half.write_all(&pkt.dest_key).await {
                        tracing::warn!("Relay TX error (key): {:?}", e);
                        break;
                    }
                    if let Err(e) = write_half.write_all(&pkt.payload).await {
                        tracing::warn!("Relay TX error (payload): {:?}", e);
                        break;
                    }
                }
            };

            let rx_task = async {
                loop {
                    // Read frame length.
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = read_half.read_exact(&mut len_buf).await {
                        tracing::debug!("Relay RX connection closed: {:?}", e);
                        break;
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                    if frame_len < 32 || frame_len > 65536 {
                        tracing::warn!("Relay: invalid frame length {}", frame_len);
                        break;
                    }

                    // Read frame body.
                    let mut frame = vec![0u8; frame_len];
                    if let Err(e) = read_half.read_exact(&mut frame).await {
                        tracing::debug!("Relay RX read error: {:?}", e);
                        break;
                    }

                    let mut from_key = [0u8; 32];
                    from_key.copy_from_slice(&frame[..32]);
                    let payload = frame[32..].to_vec();

                    if inbound_tx
                        .send(RelayedPacket { from_key, payload })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            };

            tokio::select! {
                _ = tx_task => {}
                _ = rx_task => {}
            }
            tracing::info!("Relay connection closed");
        });

        Ok((outbound_tx, inbound_rx, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal relay server that echoes frames back with the sender's key
    /// swapped into the `from_key` position.
    async fn echo_relay(listener: TcpListener) {
        let (mut stream, _addr) = listener.accept().await.unwrap();

        // Read 32-byte identity.
        let mut identity = [0u8; 32];
        stream.read_exact(&mut identity).await.unwrap();

        let (mut rd, mut wr) = stream.into_split();

        // Read one frame and echo it back with identity as from_key.
        let mut len_buf = [0u8; 4];
        rd.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u32::from_be_bytes(len_buf) as usize;

        let mut frame = vec![0u8; frame_len];
        rd.read_exact(&mut frame).await.unwrap();

        // Build echo: [len][from_key=identity][payload]
        let payload = &frame[32..];
        let echo_len = (32 + payload.len()) as u32;
        wr.write_all(&echo_len.to_be_bytes()).await.unwrap();
        wr.write_all(&identity).await.unwrap();
        wr.write_all(payload).await.unwrap();
    }

    #[tokio::test]
    async fn relay_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();

        tokio::spawn(echo_relay(listener));

        let pubkey = [0xAA; 32];
        let client = RelayClient::new(relay_addr.to_string(), pubkey);
        let (tx, mut rx, _handle) = client.connect().await.unwrap();

        // Send a packet addressed to some dest.
        let dest = [0xBB; 32];
        let payload = vec![0x03, 0x00, 0x01, 0x02, 0x03]; // fake encrypted data
        tx.send(OutboundRelayPacket {
            dest_key: dest,
            payload: payload.clone(),
        })
        .await
        .unwrap();

        // The echo relay reflects it back with our identity as from_key.
        let echoed = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("should receive within timeout")
        .expect("channel should not be closed");

        assert_eq!(echoed.from_key, pubkey);
        assert_eq!(echoed.payload, payload);
    }
}
