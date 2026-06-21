use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tun_rs::DeviceBuilder;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;

const DEFAULT_KEY: &[u8; 32] = b"araxmesh-phase0-default-32-bytes";

#[derive(Parser, Debug)]
#[command(author, version, about = "AraxMesh Phase 0 TUN-to-UDP Daemon", long_about = None)]
struct Args {
    /// Name of the TUN interface to create
    #[arg(long, default_value = "arax0")]
    tun_name: String,

    /// IP address for the TUN interface (e.g. 10.0.99.1)
    #[arg(long)]
    tun_ip: String,

    /// Netmask for the TUN interface
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,

    /// Local UDP socket address to bind (e.g. 0.0.0.0:50001)
    #[arg(long, default_value = "0.0.0.0:50001")]
    local_udp: SocketAddr,

    /// Remote peer's UDP socket address
    #[arg(long)]
    peer_udp: SocketAddr,

    /// Static 32-byte key in hex (64 hex characters)
    #[arg(long)]
    key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing/logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    tracing::info!("Starting AraxMesh Phase 0 daemon");
    tracing::info!("TUN Interface: {} (IP: {}, Netmask: {})", args.tun_name, args.tun_ip, args.tun_netmask);
    tracing::info!("Local UDP Bind: {}", args.local_udp);
    tracing::info!("Peer UDP Endpoint: {}", args.peer_udp);

    // Parse or retrieve static key
    let key_bytes = if let Some(key_hex) = args.key {
        let decoded = hex::decode(&key_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid hex key: {}", e)))?;
        if decoded.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Key must be exactly 32 bytes (64 hex characters), got {} bytes", decoded.len()),
            )
            .into());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&decoded);
        k
    } else {
        tracing::warn!("No key provided, using default static key for testing purposes");
        *DEFAULT_KEY
    };

    let cipher = Arc::new(ChaCha20Poly1305::new(Key::from_slice(&key_bytes)));

    // Create the TUN interface
    // Note: This operation requires root/administrator privileges
    let dev = DeviceBuilder::new()
        .name(&args.tun_name)
        .mtu(1420) // standard WireGuard-like MTU to leave room for headers (UDP + IP + AraxMesh)
        .ipv4(args.tun_ip.clone(), args.tun_netmask.clone(), None)
        .build_async()?;

    tracing::info!("Successfully created TUN interface: {}", dev.name()?);

    // Bind local UDP socket
    let sock = Arc::new(UdpSocket::bind(args.local_udp).await?);
    tracing::info!("Successfully bound UDP socket to {}", args.local_udp);

    // Share TUN device and UDP socket between tasks
    let dev_tx = Arc::new(dev);
    let dev_rx = dev_tx.clone();
    
    let sock_tx = sock.clone();
    let sock_rx = sock;

    let cipher_tx = cipher.clone();
    let cipher_rx = cipher;

    let peer_udp = args.peer_udp;

    // Task 1: Read IP packets from TUN, encrypt, send over UDP
    let tun_to_udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match dev_rx.recv(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        tracing::warn!("TUN read returned 0 bytes; exiting loop");
                        break;
                    }
                    let packet_payload = &buf[..n];
                    tracing::debug!("Captured packet from TUN: {} bytes", n);

                    // Generate a cryptographically random 12-byte nonce
                    let mut nonce_bytes = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);

                    // Encrypt the IP packet payload
                    match cipher_tx.encrypt(nonce, packet_payload) {
                        Ok(ciphertext) => {
                            // Construct UDP payload: [12 bytes nonce] + [ciphertext]
                            let mut udp_payload = Vec::with_capacity(12 + ciphertext.len());
                            udp_payload.extend_from_slice(&nonce_bytes);
                            udp_payload.extend_from_slice(&ciphertext);

                            if let Err(e) = sock_tx.send_to(&udp_payload, peer_udp).await {
                                tracing::error!("Failed to send UDP packet to peer {}: {:?}", peer_udp, e);
                            } else {
                                tracing::debug!("Sent encrypted packet to peer: {} bytes", udp_payload.len());
                            }
                        }
                        Err(e) => {
                            tracing::error!("Encryption failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from TUN: {:?}", e);
                }
            }
        }
    });

    // Task 2: Receive UDP packets, decrypt, write to TUN
    let udp_to_tun_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match sock_rx.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    tracing::debug!("Received UDP packet: {} bytes from {}", n, addr);

                    if n < 12 + 16 {
                        tracing::warn!("Received UDP packet too short ({} bytes); dropping", n);
                        continue;
                    }

                    // Extract nonce and ciphertext
                    let (nonce_bytes, ciphertext) = buf[..n].split_at(12);
                    let nonce = Nonce::from_slice(nonce_bytes);

                    // Decrypt the payload
                    match cipher_rx.decrypt(nonce, ciphertext) {
                        Ok(plaintext) => {
                            tracing::debug!("Decrypted packet: {} bytes; writing to TUN", plaintext.len());
                            if let Err(e) = dev_tx.send(&plaintext).await {
                                tracing::error!("Failed to write packet to TUN: {:?}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Decryption failed for packet from {}: {:?}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from UDP socket: {:?}", e);
                }
            }
        }
    });

    // Keep the application running
    tokio::select! {
        res = tun_to_udp_task => {
            tracing::info!("TUN-to-UDP task finished: {:?}", res);
        }
        res = udp_to_tun_task => {
            tracing::info!("UDP-to-TUN task finished: {:?}", res);
        }
    }

    Ok(())
}
