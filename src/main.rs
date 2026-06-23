use clap::Parser;
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tun_rs::DeviceBuilder;

struct ActiveSession {
    state: StatelessTransportState,
    tx_nonce: u64,
    established_at: Instant,
    tx_bytes: u64,
}

struct Peer {
    pubkey: Vec<u8>,
    endpoint: Option<SocketAddr>,
    allowed_ip: std::net::Ipv4Addr,

    active: Option<ActiveSession>,
    previous: Option<ActiveSession>,
    handshake: Option<HandshakeState>,
    last_handshake_attempt: Option<Instant>,
    last_handshake_packet: Option<Vec<u8>>,

    last_rx: Instant,
    last_tx: Instant,
}

impl Peer {
    fn new(pubkey: Vec<u8>, endpoint: Option<SocketAddr>, allowed_ip: std::net::Ipv4Addr) -> Self {
        Self {
            pubkey,
            endpoint,
            allowed_ip,
            active: None,
            previous: None,
            handshake: None,
            last_handshake_attempt: None,
            last_handshake_packet: None,
            last_rx: Instant::now(),
            last_tx: Instant::now(),
        }
    }

    fn initiate_handshake(&mut self, local_priv: &[u8]) -> Option<Vec<u8>> {
        let _ = self.endpoint?;

        let mut builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        builder = builder.local_private_key(local_priv);
        builder = builder.remote_public_key(&self.pubkey);

        match builder.build_initiator() {
            Ok(mut hs) => {
                let mut msg = vec![0u8; 128];
                match hs.write_message(&[], &mut msg) {
                    Ok(len) => {
                        msg.truncate(len);

                        let mut packet = Vec::with_capacity(1 + len);
                        packet.push(0x01);
                        packet.extend_from_slice(&msg);

                        self.handshake = Some(hs);
                        self.last_handshake_attempt = Some(Instant::now());
                        self.last_handshake_packet = Some(packet.clone());
                        self.last_tx = Instant::now();

                        Some(packet)
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to write handshake message for peer {}: {:?}",
                            hex::encode(&self.pubkey),
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to build initiator handshake for peer {}: {:?}",
                    hex::encode(&self.pubkey),
                    e
                );
                None
            }
        }
    }

    fn handle_handshake_packet(
        &mut self,
        local_priv: &[u8],
        packet_type: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        match packet_type {
            0x01 => {
                let mut builder =
                    Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
                builder = builder.local_private_key(local_priv);

                match builder.build_responder() {
                    Ok(mut hs) => {
                        let mut read_buf = vec![0u8; 128];
                        if let Err(e) = hs.read_message(payload, &mut read_buf) {
                            tracing::error!("Failed to read handshake initiation: {:?}", e);
                            return None;
                        }

                        if let Some(remote_static) = hs.get_remote_static() {
                            if remote_static != self.pubkey {
                                tracing::error!(
                                    "Handshake authentication failed: remote static key does not match peer's key"
                                );
                                return None;
                            }
                        } else {
                            tracing::error!(
                                "Handshake authentication failed: remote static key not present"
                            );
                            return None;
                        }

                        let mut resp_msg = vec![0u8; 128];
                        match hs.write_message(&[], &mut resp_msg) {
                            Ok(len) => {
                                resp_msg.truncate(len);

                                match hs.into_stateless_transport_mode() {
                                    Ok(stateless_transport) => {
                                        tracing::info!(
                                            "Handshake complete for peer {}. Transitioning to Transport mode.",
                                            hex::encode(&self.pubkey)
                                        );

                                        if let Some(active) = self.active.take() {
                                            self.previous = Some(active);
                                        }

                                        self.active = Some(ActiveSession {
                                            state: stateless_transport,
                                            tx_nonce: 0,
                                            established_at: Instant::now(),
                                            tx_bytes: 0,
                                        });
                                        self.last_rx = Instant::now();
                                        self.last_tx = Instant::now();

                                        let mut resp_packet = Vec::with_capacity(1 + len);
                                        resp_packet.push(0x02);
                                        resp_packet.extend_from_slice(&resp_msg);
                                        Some(resp_packet)
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to transition to stateless transport: {:?}",
                                            e
                                        );
                                        None
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to write handshake response: {:?}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to build responder handshake: {:?}", e);
                        None
                    }
                }
            }
            0x02 => {
                if let Some(mut hs) = self.handshake.take() {
                    let mut read_buf = vec![0u8; 128];
                    if let Err(e) = hs.read_message(payload, &mut read_buf) {
                        tracing::error!("Failed to read handshake response: {:?}", e);
                        self.handshake = Some(hs);
                        return None;
                    }

                    match hs.into_stateless_transport_mode() {
                        Ok(stateless_transport) => {
                            tracing::info!(
                                "Handshake complete for peer {}. Transitioning to Transport mode.",
                                hex::encode(&self.pubkey)
                            );

                            if let Some(active) = self.active.take() {
                                self.previous = Some(active);
                            }

                            self.active = Some(ActiveSession {
                                state: stateless_transport,
                                tx_nonce: 0,
                                established_at: Instant::now(),
                                tx_bytes: 0,
                            });

                            self.handshake = None;
                            self.last_handshake_attempt = None;
                            self.last_handshake_packet = None;
                            self.last_rx = Instant::now();
                            self.last_tx = Instant::now();
                        }
                        Err(e) => {
                            tracing::error!("Failed to transition to stateless transport: {:?}", e);
                        }
                    }
                } else {
                    tracing::warn!(
                        "Received handshake response for peer {} but no handshake is in progress",
                        hex::encode(&self.pubkey)
                    );
                }
                None
            }
            _ => None,
        }
    }

    fn encrypt_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let active = self.active.as_mut()?;
        let nonce = active.tx_nonce;
        active.tx_nonce += 1;
        active.tx_bytes += payload.len() as u64;

        let mut ciphertext = vec![0u8; payload.len() + 16];
        match active.state.write_message(nonce, payload, &mut ciphertext) {
            Ok(len) => {
                ciphertext.truncate(len);
                self.last_tx = Instant::now();

                let mut packet = Vec::with_capacity(1 + 8 + ciphertext.len());
                packet.push(0x03);
                packet.extend_from_slice(&nonce.to_be_bytes());
                packet.extend_from_slice(&ciphertext);
                Some(packet)
            }
            Err(e) => {
                tracing::error!("Failed to encrypt packet with nonce {}: {:?}", nonce, e);
                None
            }
        }
    }

    fn decrypt_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 8 {
            return None;
        }
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&payload[0..8]);
        let nonce = u64::from_be_bytes(nonce_bytes);
        let ciphertext = &payload[8..];

        if ciphertext.len() < 16 {
            return None;
        }
        let mut plaintext = vec![0u8; ciphertext.len() - 16];

        if let Some(active) = &self.active {
            if let Ok(len) = active.state.read_message(nonce, ciphertext, &mut plaintext) {
                plaintext.truncate(len);
                self.last_rx = Instant::now();
                return Some(plaintext);
            }
        }

        if let Some(prev) = &self.previous {
            if prev.established_at.elapsed().as_secs() < 15 {
                if let Ok(len) = prev.state.read_message(nonce, ciphertext, &mut plaintext) {
                    plaintext.truncate(len);
                    self.last_rx = Instant::now();
                    return Some(plaintext);
                }
            }
        }

        None
    }

    fn check_rotation(&mut self) -> bool {
        if let Some(prev) = &self.previous {
            if prev.established_at.elapsed().as_secs() >= 15 {
                self.previous = None;
            }
        }

        if let Some(active) = &self.active {
            let time_expired = active.established_at.elapsed().as_secs() > 120;
            let volume_expired = active.tx_bytes > 1_000_000_000;
            time_expired || volume_expired
        } else {
            false
        }
    }
}

struct PeerManager {
    local_priv: Vec<u8>,
    peers: Vec<Peer>,
}

impl PeerManager {
    fn new(local_priv: Vec<u8>, peers: Vec<Peer>) -> Self {
        Self { local_priv, peers }
    }
}

fn parse_ipv4_header(packet: &[u8]) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

struct ParsedPeer {
    pubkey: Vec<u8>,
    endpoint: Option<SocketAddr>,
    allowed_ip: std::net::Ipv4Addr,
}

fn parse_peer_arg(s: &str) -> Result<ParsedPeer, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split(';').collect();
    if parts.len() != 3 {
        return Err(format!(
            "Invalid peer format: '{}'. Expected 'pubkey_hex;[endpoint];allowed_ip'",
            s
        )
        .into());
    }

    let pubkey_hex = parts[0];
    let endpoint_str = parts[1];
    let allowed_ip_str = parts[2];

    let pubkey = hex::decode(pubkey_hex)
        .map_err(|e| format!("Invalid public key hex '{}': {}", pubkey_hex, e))?;
    if pubkey.len() != 32 {
        return Err(format!(
            "Public key must be exactly 32 bytes (64 hex characters), got {} bytes",
            pubkey.len()
        )
        .into());
    }

    let endpoint = if endpoint_str.is_empty() {
        None
    } else {
        Some(
            endpoint_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid endpoint address '{}': {}", endpoint_str, e))?,
        )
    };

    let allowed_ip = allowed_ip_str
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| format!("Invalid allowed IP '{}': {}", allowed_ip_str, e))?;

    Ok(ParsedPeer {
        pubkey,
        endpoint,
        allowed_ip,
    })
}

#[derive(Parser, Debug)]
#[command(author, version, about = "AraxMesh Phase 2 TUN-to-UDP Daemon", long_about = None)]
struct Args {
    /// Name of the TUN interface to create
    #[arg(long, default_value = "arax0")]
    tun_name: String,

    /// IP address for the TUN interface (e.g. 10.0.99.1)
    #[arg(long)]
    tun_ip: Option<String>,

    /// Netmask for the TUN interface
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: String,

    /// Local UDP socket address to bind (e.g. 0.0.0.0:50001)
    #[arg(long, default_value = "0.0.0.0:50001")]
    local_udp: SocketAddr,

    /// Peer configuration in format "pubkey_hex;[endpoint];allowed_ip" (can be repeated)
    #[arg(long, action = clap::ArgAction::Append)]
    peer: Vec<String>,

    /// Local static private key in hex (64 hex characters)
    #[arg(long)]
    private_key: Option<String>,

    /// Generate a new Noise static keypair and exit
    #[arg(long)]
    gen_keys: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    if args.gen_keys {
        let builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        println!("Private Key (hex): {}", hex::encode(keypair.private));
        println!("Public Key (hex): {}", hex::encode(keypair.public));
        return Ok(());
    }

    let tun_ip = args.tun_ip.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing required argument: --tun-ip",
        )
    })?;
    let private_key_hex = args.private_key.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing required argument: --private-key",
        )
    })?;

    let local_priv = hex::decode(&private_key_hex).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid private-key hex: {}", e),
        )
    })?;
    if local_priv.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Private key must be exactly 32 bytes (64 hex characters), got {} bytes",
                local_priv.len()
            ),
        )
        .into());
    }

    let mut peers = Vec::new();
    for p_str in args.peer {
        let parsed = parse_peer_arg(&p_str)?;
        peers.push(Peer::new(parsed.pubkey, parsed.endpoint, parsed.allowed_ip));
    }

    if peers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "At least one peer configuration must be provided via --peer",
        )
        .into());
    }

    tracing::info!("Starting AraxMesh Phase 2 daemon");
    tracing::info!(
        "TUN Interface: {} (IP: {}, Netmask: {})",
        args.tun_name,
        tun_ip,
        args.tun_netmask
    );
    tracing::info!("Local UDP Bind: {}", args.local_udp);
    for peer in &peers {
        tracing::info!(
            "Configured Peer: allowed_ip={}, pubkey={}, endpoint={:?}",
            peer.allowed_ip,
            hex::encode(&peer.pubkey),
            peer.endpoint
        );
    }

    let pm = Arc::new(std::sync::Mutex::new(PeerManager::new(local_priv, peers)));

    let dev = DeviceBuilder::new()
        .name(&args.tun_name)
        .mtu(1411) // 1420 - 9 bytes AraxMesh overhead (1 byte type + 8 bytes nonce)
        .ipv4(tun_ip.clone(), args.tun_netmask.clone(), None)
        .build_async()?;

    tracing::info!("Successfully created TUN interface: {}", dev.name()?);

    let sock = Arc::new(UdpSocket::bind(args.local_udp).await?);
    tracing::info!("Successfully bound UDP socket to {}", args.local_udp);

    let dev_tx = Arc::new(dev);
    let dev_rx = dev_tx.clone();

    let sock_tx = sock.clone();
    let sock_rx = sock.clone();

    let pm_tx = pm.clone();
    let pm_rx = pm.clone();

    // Handshake retransmission, keepalive, key rotation timer
    let session_timer = pm.clone();
    let sock_timer = sock.clone();
    let timer_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;

            let mut actions = Vec::new();
            {
                let mut manager = session_timer.lock().unwrap();
                let local_priv = manager.local_priv.clone();

                for peer in manager.peers.iter_mut() {
                    // 1. Check rotation
                    if peer.check_rotation() && peer.handshake.is_none() {
                        tracing::info!(
                            "Key rotation triggered for peer {}. Initiating handshake...",
                            hex::encode(&peer.pubkey)
                        );
                        if let Some(packet) = peer.initiate_handshake(&local_priv) {
                            actions.push((packet, peer.endpoint));
                        }
                    }

                    // 2. Check dead session detection
                    if peer.active.is_some() && peer.last_rx.elapsed().as_secs() >= 15 {
                        tracing::warn!(
                            "Session dead for peer {} (no rx for 15s). Clearing keys.",
                            hex::encode(&peer.pubkey)
                        );
                        peer.active = None;
                        peer.previous = None;
                    }

                    // 3. Check keepalive
                    if peer.active.is_some() && peer.last_tx.elapsed().as_secs() >= 10 {
                        tracing::debug!("Sending keepalive to peer {}", hex::encode(&peer.pubkey));
                        if let Some(packet) = peer.encrypt_packet(&[]) {
                            actions.push((packet, peer.endpoint));
                        }
                    }

                    // 4. Retransmit or initiate handshake if no active session and endpoint is known
                    if peer.active.is_none() && peer.handshake.is_none() && peer.endpoint.is_some()
                    {
                        tracing::info!(
                            "No active session for peer {}. Initiating handshake...",
                            hex::encode(&peer.pubkey)
                        );
                        if let Some(packet) = peer.initiate_handshake(&local_priv) {
                            actions.push((packet, peer.endpoint));
                        }
                    } else if let Some(attempt) = peer.last_handshake_attempt {
                        if attempt.elapsed().as_secs() >= 2 {
                            tracing::info!(
                                "Handshake timeout for peer {}. Retransmitting...",
                                hex::encode(&peer.pubkey)
                            );
                            peer.last_handshake_attempt = Some(Instant::now());
                            if let Some(packet) = &peer.last_handshake_packet {
                                actions.push((packet.clone(), peer.endpoint));
                            }
                        }
                    }
                }
            }

            for (packet, endpoint) in actions {
                if let Some(addr) = endpoint {
                    if let Err(e) = sock_timer.send_to(&packet, addr).await {
                        tracing::error!("Failed to send timer packet to {}: {:?}", addr, e);
                    }
                }
            }
        }
    });

    // Task 1: Read IP packets from TUN, route to peer, encrypt, send over UDP
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

                    if let Some((_src_ip, dst_ip)) = parse_ipv4_header(packet_payload) {
                        tracing::debug!("TUN captured packet: {} bytes destined to {}", n, dst_ip);

                        let mut action = None;

                        {
                            let mut manager = pm_tx.lock().unwrap();
                            let local_priv = manager.local_priv.clone();

                            if let Some(peer) =
                                manager.peers.iter_mut().find(|p| p.allowed_ip == dst_ip)
                            {
                                if let Some(packet) = peer.encrypt_packet(packet_payload) {
                                    action = Some((packet, peer.endpoint));
                                } else if peer.active.is_none() && peer.handshake.is_none() {
                                    if let Some(hs_packet) = peer.initiate_handshake(&local_priv) {
                                        tracing::info!(
                                            "Triggering handshake for peer {} at allowed IP {}",
                                            hex::encode(&peer.pubkey),
                                            peer.allowed_ip
                                        );
                                        action = Some((hs_packet, peer.endpoint));
                                    }
                                }
                            } else {
                                tracing::debug!("No routed peer for dst IP: {}", dst_ip);
                            }
                        }

                        if let Some((packet, Some(endpoint))) = action {
                            if let Err(e) = sock_tx.send_to(&packet, endpoint).await {
                                tracing::error!(
                                    "Failed to send UDP packet to peer {}: {:?}",
                                    endpoint,
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from TUN: {:?}", e);
                }
            }
        }
    });

    // Task 2: Receive UDP packets, decrypt/process, write to TUN if data
    let udp_to_tun_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match sock_rx.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    tracing::debug!("Received UDP packet: {} bytes from {}", n, addr);

                    if n == 0 {
                        continue;
                    }

                    let packet_type = buf[0];
                    let payload = &buf[1..n];

                    if packet_type == 0x01 {
                        let resp = {
                            let mut manager = pm_rx.lock().unwrap();
                            let local_priv = manager.local_priv.clone();
                            let mut response_packet = None;

                            let mut builder =
                                Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
                            builder = builder.local_private_key(&local_priv);

                            if let Ok(mut hs) = builder.build_responder() {
                                let mut read_buf = vec![0u8; 128];
                                if hs.read_message(payload, &mut read_buf).is_ok() {
                                    if let Some(remote_static_ref) = hs.get_remote_static() {
                                        let remote_static = remote_static_ref.to_vec();
                                        if let Some(peer) = manager
                                            .peers
                                            .iter_mut()
                                            .find(|p| p.pubkey == remote_static)
                                        {
                                            peer.endpoint = Some(addr);

                                            let mut resp_msg = vec![0u8; 128];
                                            if let Ok(len) = hs.write_message(&[], &mut resp_msg) {
                                                resp_msg.truncate(len);
                                                if let Ok(stateless_transport) =
                                                    hs.into_stateless_transport_mode()
                                                {
                                                    tracing::info!(
                                                        "Handshake complete for peer {} (initiator). Transitioning to Transport mode.",
                                                        hex::encode(remote_static)
                                                    );

                                                    if let Some(active) = peer.active.take() {
                                                        peer.previous = Some(active);
                                                    }

                                                    peer.active = Some(ActiveSession {
                                                        state: stateless_transport,
                                                        tx_nonce: 0,
                                                        established_at: Instant::now(),
                                                        tx_bytes: 0,
                                                    });
                                                    peer.last_rx = Instant::now();
                                                    peer.last_tx = Instant::now();

                                                    let mut resp_packet =
                                                        Vec::with_capacity(1 + len);
                                                    resp_packet.push(0x02);
                                                    resp_packet.extend_from_slice(&resp_msg);
                                                    response_packet = Some(resp_packet);
                                                }
                                            }
                                        } else {
                                            tracing::warn!(
                                                "Unauthorized remote static key in handshake initiation: {}",
                                                hex::encode(remote_static)
                                            );
                                        }
                                    }
                                }
                            }
                            response_packet
                        };

                        if let Some(resp_packet) = resp {
                            if let Err(e) = sock_rx.send_to(&resp_packet, addr).await {
                                tracing::error!("Failed to send handshake response: {:?}", e);
                            }
                        }
                    } else if packet_type == 0x02 {
                        {
                            let mut manager = pm_rx.lock().unwrap();
                            let local_priv = manager.local_priv.clone();
                            if let Some(peer) =
                                manager.peers.iter_mut().find(|p| p.endpoint == Some(addr))
                            {
                                peer.handle_handshake_packet(&local_priv, packet_type, payload);
                            } else {
                                tracing::warn!(
                                    "Received handshake response from unknown endpoint: {}",
                                    addr
                                );
                            }
                        }
                    } else if packet_type == 0x03 {
                        let decrypted = {
                            let mut manager = pm_rx.lock().unwrap();
                            let mut result = None;

                            // 1. Try by endpoint lookup
                            if let Some(peer) =
                                manager.peers.iter_mut().find(|p| p.endpoint == Some(addr))
                            {
                                if let Some(plaintext) = peer.decrypt_packet(payload) {
                                    if let Some((src_ip, _dst_ip)) = parse_ipv4_header(&plaintext) {
                                        if src_ip == peer.allowed_ip {
                                            result = Some(plaintext);
                                        } else {
                                            tracing::warn!(
                                                "Cryptokey routing check failed: src_ip {} does not match peer's allowed IP {}",
                                                src_ip,
                                                peer.allowed_ip
                                            );
                                        }
                                    }
                                }
                            }

                            // 2. Try trial decryption fallback
                            if result.is_none() {
                                for peer in manager.peers.iter_mut() {
                                    if peer.endpoint != Some(addr) {
                                        if let Some(plaintext) = peer.decrypt_packet(payload) {
                                            if let Some((src_ip, _dst_ip)) =
                                                parse_ipv4_header(&plaintext)
                                            {
                                                if src_ip == peer.allowed_ip {
                                                    tracing::info!(
                                                        "Peer {} roamed to new endpoint: {}",
                                                        hex::encode(&peer.pubkey),
                                                        addr
                                                    );
                                                    peer.endpoint = Some(addr);
                                                    result = Some(plaintext);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            result
                        };

                        if let Some(plaintext) = decrypted {
                            if !plaintext.is_empty() {
                                if let Err(e) = dev_tx.send(&plaintext).await {
                                    tracing::error!("Failed to write packet to TUN: {:?}", e);
                                }
                            } else {
                                tracing::debug!("Received keepalive data packet from {}", addr);
                            }
                        } else {
                            tracing::warn!(
                                "Decryption failed or invalid data packet from {}",
                                addr
                            );
                        }
                    } else {
                        tracing::warn!(
                            "Received unknown packet type {} from {}",
                            packet_type,
                            addr
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from UDP socket: {:?}", e);
                }
            }
        }
    });

    tokio::select! {
        res = tun_to_udp_task => {
            tracing::info!("TUN-to-UDP task finished: {:?}", res);
        }
        res = udp_to_tun_task => {
            tracing::info!("UDP-to-TUN task finished: {:?}", res);
        }
        res = timer_task => {
            tracing::info!("Timer task finished: {:?}", res);
        }
    }

    Ok(())
}
