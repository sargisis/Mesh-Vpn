//! AraxMesh data-plane daemon: peer/session state and the runtime loop.

use crate::config::{Startup, parse_peer_arg, parse_startup};
use crate::control::{PollRequest, PollResponse, RegisterRequest, RegisterResponse};
use crate::nat::{self, PROBE_PACKET_TYPE};
use crate::packet::parse_ipv4_header;
use crate::types::PeerDescriptor;
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tun_rs::DeviceBuilder;
use crate::relay::{OutboundRelayPacket, RelayedPacket, RelayClient};


struct ActiveSession {
    state: StatelessTransportState,
    tx_nonce: u64,
    established_at: Instant,
    tx_bytes: u64,
}

#[derive(Debug, Clone)]
enum OutboundDest {
    Udp(SocketAddr),
    Relay([u8; 32]),
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
    last_direct_rx: Instant,
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
            last_direct_rx: Instant::now(),
        }
    }

    fn determine_dest(&self, has_relay: bool) -> Option<OutboundDest> {
        if has_relay && (self.endpoint.is_none() || self.last_direct_rx.elapsed().as_secs() >= 10) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&self.pubkey);
            Some(OutboundDest::Relay(key))
        } else {
            self.endpoint.map(OutboundDest::Udp)
        }
    }

    fn initiate_handshake(&mut self, local_priv: &[u8]) -> Option<Vec<u8>> {

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

        if let Some(active) = &self.active
            && let Ok(len) = active.state.read_message(nonce, ciphertext, &mut plaintext)
        {
            plaintext.truncate(len);
            self.last_rx = Instant::now();
            return Some(plaintext);
        }

        if let Some(prev) = &self.previous
            && prev.established_at.elapsed().as_secs() < 15
            && let Ok(len) = prev.state.read_message(nonce, ciphertext, &mut plaintext)
        {
            plaintext.truncate(len);
            self.last_rx = Instant::now();
            return Some(plaintext);
        }

        None
    }

    fn check_rotation(&mut self) -> bool {
        if let Some(prev) = &self.previous
            && prev.established_at.elapsed().as_secs() >= 15
        {
            self.previous = None;
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

    /// Reconcile the peer table with the set advertised by the coordinator:
    /// add peers we don't have, update the endpoint/allowed_ip of ones we do
    /// (keeping their live Noise sessions rather than tearing them down), and
    /// drop peers the coordinator no longer lists. Malformed descriptors are
    /// logged and skipped — a bad control-plane entry must not abort the sync.
    ///
    /// Returns the endpoints of newly added peers (for hole-punching).
    #[allow(dead_code)]
    fn sync_peers(&mut self, descriptors: &[PeerDescriptor]) -> Vec<std::net::SocketAddr> {
        let mut wanted = Vec::new();
        for d in descriptors {
            match parse_peer_arg(&d.to_spec()) {
                Ok(p) => wanted.push(p),
                Err(e) => {
                    tracing::warn!("Skipping invalid peer descriptor from coordinator: {}", e)
                }
            }
        }

        // Drop peers no longer present upstream.
        self.peers
            .retain(|p| wanted.iter().any(|w| w.pubkey == p.pubkey));

        // Add new peers; update existing ones in place to preserve sessions.
        let mut new_endpoints = Vec::new();
        for w in wanted {
            if let Some(existing) = self.peers.iter_mut().find(|p| p.pubkey == w.pubkey) {
                existing.endpoint = w.endpoint;
                existing.allowed_ip = w.allowed_ip;
            } else {
                if let Some(ep) = w.endpoint {
                    new_endpoints.push(ep);
                    self.peers
                        .push(Peer::new(w.pubkey, Some(ep), w.allowed_ip));
                } else {
                    self.peers
                        .push(Peer::new(w.pubkey, None, w.allowed_ip));
                }
            }
        }
        new_endpoints
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let settings = match parse_startup()? {
        Startup::GenKeys => {
            let builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
            let keypair = builder.generate_keypair().unwrap();
            println!("Private Key (hex): {}", hex::encode(keypair.private));
            println!("Public Key (hex): {}", hex::encode(keypair.public));
            return Ok(());
        }
        Startup::Run(s) => s,
    };

    let local_priv = hex::decode(&settings.private_key_hex).map_err(|e| {
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

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&local_priv);
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    let pubkey_bytes = public.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);

    let public_endpoint = if let Some(ep) = &settings.public_endpoint {
        ep.clone()
    } else {
        settings.local_udp.to_string()
    };

    let (tun_ip, peers) = if let Some(coord_url) = &settings.coordinator_url {
        let http_client = reqwest::Client::new();
        let reg_url = format!("{}/register", coord_url.trim_end_matches('/'));
        let reg_req = RegisterRequest {
            public_key: pubkey_hex.clone(),
            auth_key: settings.auth_key.clone().unwrap_or_default(),
            endpoint: public_endpoint.clone(),
            hostname: settings.hostname.clone(),
        };

        tracing::info!("Registering with coordinator at {}...", reg_url);
        let reg_resp: RegisterResponse = http_client
            .post(&reg_url)
            .json(&reg_req)
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Registration failed: {}", e)))?
            .json()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Invalid registration response: {}", e)))?;

        tracing::info!("Successfully registered. Assigned IP: {}", reg_resp.assigned_ip);
        if let Some(ref obs) = reg_resp.observed_endpoint {
            tracing::info!("Observed external endpoint (STUN-like): {}", obs);
        }

        let mut parsed_peers = Vec::new();
        for p_desc in reg_resp.peers {
            match parse_peer_arg(&p_desc.to_spec()) {
                Ok(parsed) => {
                    parsed_peers.push(Peer::new(parsed.pubkey, parsed.endpoint, parsed.allowed_ip));
                }
                Err(e) => {
                    tracing::warn!("Failed to parse peer from coordinator: {}", e);
                }
            }
        }
        (reg_resp.assigned_ip, parsed_peers)
    } else {
        let mut parsed_peers = Vec::new();
        for p_str in &settings.peer_specs {
            let parsed = parse_peer_arg(p_str)?;
            parsed_peers.push(Peer::new(parsed.pubkey, parsed.endpoint, parsed.allowed_ip));
        }

        if parsed_peers.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "At least one peer must be configured (via --peer or [[peer]] in --config)",
            )
            .into());
        }
        let static_tun_ip = settings.tun_ip.clone().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing tun_ip")
        })?;
        (static_tun_ip, parsed_peers)
    };

    tracing::info!("Starting AraxMesh Phase 3 daemon");
    tracing::info!(
        "TUN Interface: {} (IP: {}, Netmask: {})",
        settings.tun_name,
        tun_ip,
        settings.tun_netmask
    );
    tracing::info!("Local UDP Bind: {}", settings.local_udp);
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
        .name(&settings.tun_name)
        .mtu(1411) // 1420 - 9 bytes AraxMesh overhead (1 byte type + 8 bytes nonce)
        .ipv4(tun_ip.clone(), settings.tun_netmask.clone(), None)
        .build_async()?;

    tracing::info!("Successfully created TUN interface: {}", dev.name()?);

    let sock = Arc::new(UdpSocket::bind(settings.local_udp).await?);
    tracing::info!("Successfully bound UDP socket to {}", settings.local_udp);

    let dev_tx = Arc::new(dev);
    let dev_rx = dev_tx.clone();
    let dev_tx_relay = dev_tx.clone();

    let sock_tx = sock.clone();
    let sock_rx = sock.clone();

    let pm_tx = pm.clone();
    let pm_rx = pm.clone();

    let (relay_send_tx, mut relay_send_rx) = mpsc::channel::<OutboundRelayPacket>(128);
    let has_relay = settings.relay_addr.is_some();
    let relay_tx_timer = if has_relay { Some(relay_send_tx.clone()) } else { None };
    let relay_tx_tun = if has_relay { Some(relay_send_tx.clone()) } else { None };

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
                            if let Some(dest) = peer.determine_dest(has_relay) {
                                actions.push((packet, dest));
                            }
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
                            if let Some(dest) = peer.determine_dest(has_relay) {
                                actions.push((packet, dest));
                            }
                        }
                    }

                    // 4. Retransmit or initiate handshake if no active session
                    if peer.active.is_none() && peer.handshake.is_none() && (peer.endpoint.is_some() || has_relay)
                    {
                        tracing::info!(
                            "No active session for peer {}. Initiating handshake...",
                            hex::encode(&peer.pubkey)
                        );
                        if let Some(packet) = peer.initiate_handshake(&local_priv) {
                            if let Some(dest) = peer.determine_dest(has_relay) {
                                actions.push((packet, dest));
                            }
                        }
                    } else if let Some(attempt) = peer.last_handshake_attempt
                        && attempt.elapsed().as_secs() >= 2
                    {
                        tracing::info!(
                            "Handshake timeout for peer {}. Retransmitting...",
                            hex::encode(&peer.pubkey)
                        );
                        peer.last_handshake_attempt = Some(Instant::now());
                        if let Some(packet) = &peer.last_handshake_packet {
                            if let Some(dest) = peer.determine_dest(has_relay) {
                                actions.push((packet.clone(), dest));
                            }
                        }
                    }
                }
            }

            for (packet, dest) in actions {
                match dest {
                    OutboundDest::Udp(addr) => {
                        if let Err(e) = sock_timer.send_to(&packet, addr).await {
                            tracing::error!("Failed to send timer packet to {}: {:?}", addr, e);
                        }
                    }
                    OutboundDest::Relay(dest_key) => {
                        if let Some(ref tx) = relay_tx_timer {
                            let _ = tx.send(OutboundRelayPacket { dest_key, payload: packet }).await;
                        }
                    }
                }
            }
        }
    });

    // Task 1: Read IP packets from TUN, route to peer, encrypt, send over UDP or Relay
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
                                    if let Some(dest) = peer.determine_dest(has_relay) {
                                        action = Some((packet, dest));
                                    }
                                } else if peer.active.is_none()
                                    && peer.handshake.is_none()
                                    && let Some(hs_packet) = peer.initiate_handshake(&local_priv)
                                {
                                    tracing::info!(
                                        "Triggering handshake for peer {} at allowed IP {}",
                                        hex::encode(&peer.pubkey),
                                        peer.allowed_ip
                                    );
                                    if let Some(dest) = peer.determine_dest(has_relay) {
                                        action = Some((hs_packet, dest));
                                    }
                                }
                            } else {
                                tracing::debug!("No routed peer for dst IP: {}", dst_ip);
                            }
                        }

                        if let Some((packet, dest)) = action {
                            match dest {
                                OutboundDest::Udp(endpoint) => {
                                    if let Err(e) = sock_tx.send_to(&packet, endpoint).await {
                                        tracing::error!(
                                            "Failed to send UDP packet to peer {}: {:?}",
                                            endpoint,
                                            e
                                        );
                                    }
                                }
                                OutboundDest::Relay(dest_key) => {
                                    if let Some(ref tx) = relay_tx_tun {
                                        let _ = tx.send(OutboundRelayPacket { dest_key, payload: packet }).await;
                                    }
                                }
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
                                if hs.read_message(payload, &mut read_buf).is_ok()
                                    && let Some(remote_static_ref) = hs.get_remote_static()
                                {
                                    let remote_static = remote_static_ref.to_vec();
                                    if let Some(peer) =
                                        manager.peers.iter_mut().find(|p| p.pubkey == remote_static)
                                    {
                                        peer.endpoint = Some(addr);
                                        peer.last_direct_rx = Instant::now();

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

                                                let mut resp_packet = Vec::with_capacity(1 + len);
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
                            response_packet
                        };

                        if let Some(resp_packet) = resp
                            && let Err(e) = sock_rx.send_to(&resp_packet, addr).await
                        {
                            tracing::error!("Failed to send handshake response: {:?}", e);
                        }
                    } else if packet_type == 0x02 {
                        {
                            let mut manager = pm_rx.lock().unwrap();
                            let local_priv = manager.local_priv.clone();
                            if let Some(peer) =
                                manager.peers.iter_mut().find(|p| p.endpoint == Some(addr))
                            {
                                peer.handle_handshake_packet(&local_priv, packet_type, payload);
                                peer.last_direct_rx = Instant::now();
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
                                && let Some(plaintext) = peer.decrypt_packet(payload)
                                && let Some((src_ip, _dst_ip)) = parse_ipv4_header(&plaintext)
                            {
                                if src_ip == peer.allowed_ip {
                                    peer.last_direct_rx = Instant::now();
                                    result = Some(plaintext);
                                } else {
                                    tracing::warn!(
                                        "Cryptokey routing check failed: src_ip {} does not match peer's allowed IP {}",
                                        src_ip,
                                        peer.allowed_ip
                                    );
                                }
                            }

                            // 2. Try trial decryption fallback
                            if result.is_none() {
                                for peer in manager.peers.iter_mut() {
                                    if peer.endpoint != Some(addr)
                                        && let Some(plaintext) = peer.decrypt_packet(payload)
                                        && let Some((src_ip, _dst_ip)) =
                                            parse_ipv4_header(&plaintext)
                                        && src_ip == peer.allowed_ip
                                    {
                                        tracing::info!(
                                            "Peer {} roamed to new endpoint: {}",
                                            hex::encode(&peer.pubkey),
                                            addr
                                        );
                                        peer.endpoint = Some(addr);
                                        peer.last_direct_rx = Instant::now();
                                        result = Some(plaintext);
                                        break;
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
                    } else if packet_type == PROBE_PACKET_TYPE {
                        // Hole-punch probe: the sender is trying to open a
                        // NAT mapping.  We log it and optionally update the
                        // peer's endpoint if we can identify it.
                        tracing::debug!(
                            "Received hole-punch probe from {} (NAT mapping opened)",
                            addr
                        );
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

    let poll_task = if settings.coordinator_url.is_some() {
        let coordinator_url = settings.coordinator_url.clone();
        let auth_key = settings.auth_key.clone().unwrap_or_default();
        let http_client = reqwest::Client::new();
        let pm_poll = pm.clone();
        let sock_poll = sock.clone();
        let pubkey_hex = pubkey_hex.clone();
        let public_endpoint = public_endpoint.clone();
        tokio::spawn(async move {
            let coord_url = coordinator_url.unwrap();
            let poll_url = format!("{}/poll", coord_url.trim_end_matches('/'));
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                let poll_req = PollRequest {
                    public_key: pubkey_hex.clone(),
                    auth_key: auth_key.clone(),
                    endpoint: public_endpoint.clone(),
                };

                match http_client.post(&poll_url).json(&poll_req).send().await {
                    Ok(resp) => {
                        match resp.json::<PollResponse>().await {
                            Ok(poll_resp) => {
                                tracing::debug!("Successfully polled coordinator. Reconciling {} peers.", poll_resp.peers.len());
                                let new_endpoints = {
                                    let mut manager = pm_poll.lock().unwrap();
                                    manager.sync_peers(&poll_resp.peers)
                                };
                                // Punch holes for any newly discovered peers.
                                for ep in new_endpoints {
                                    tracing::info!("New peer discovered at {}; initiating hole punch", ep);
                                    let s = sock_poll.clone();
                                    tokio::spawn(async move {
                                        nat::punch_hole(&s, ep).await;
                                    });
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse poll response: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to poll coordinator: {:?}", e);
                    }
                }
            }
        })
    } else {
        tokio::spawn(std::future::pending::<()>())
    };

    let relay_task = if let Some(ref relay_addr) = settings.relay_addr {
        let relay_addr = relay_addr.clone();
        let local_pubkey = pubkey_bytes;
        let pm_relay = pm.clone();
        let relay_send_tx_clone = relay_send_tx.clone();

        tokio::spawn(async move {
            loop {
                tracing::info!("Connecting to relay server at {}...", relay_addr);
                let client = RelayClient::new(relay_addr.clone(), local_pubkey);
                match client.connect().await {
                    Ok((relay_client_tx, mut relay_client_rx, connection_handle)) => {
                        tracing::info!("Relay connection established");

                        let tx_forward = async {
                            while let Some(pkt) = relay_send_rx.recv().await {
                                if relay_client_tx.send(pkt).await.is_err() {
                                    break;
                                }
                            }
                        };

                        let rx_forward = async {
                            while let Some(pkt) = relay_client_rx.recv().await {
                                if let Some(resp) = process_relayed_packet(&pm_relay, &dev_tx_relay, pkt).await {
                                    let _ = relay_send_tx_clone.send(resp).await;
                                }
                            }
                        };

                        tokio::select! {
                            _ = connection_handle => {
                                tracing::warn!("Relay connection task finished");
                            }
                            _ = tx_forward => {
                                tracing::warn!("Relay send forwarder finished");
                            }
                            _ = rx_forward => {
                                tracing::warn!("Relay receive forwarder finished");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to relay: {:?}", e);
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        })
    } else {
        tokio::spawn(std::future::pending::<()>())
    };

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
        res = poll_task => {
            tracing::info!("Coordinator poll task finished: {:?}", res);
        }
        res = relay_task => {
            tracing::info!("Relay task finished: {:?}", res);
        }
    }

    Ok(())
}

async fn process_relayed_packet(
    pm: &Arc<std::sync::Mutex<PeerManager>>,
    dev_tx: &Arc<tun_rs::AsyncDevice>,
    pkt: RelayedPacket,
) -> Option<OutboundRelayPacket> {
    let packet_type = if pkt.payload.is_empty() {
        return None;
    } else {
        pkt.payload[0]
    };
    let payload = &pkt.payload[1..];

    if packet_type == 0x01 {
        let mut manager = pm.lock().unwrap();
        let local_priv = manager.local_priv.clone();

        let mut builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        builder = builder.local_private_key(&local_priv);

        if let Ok(mut hs) = builder.build_responder() {
            let mut read_buf = vec![0u8; 128];
            if hs.read_message(payload, &mut read_buf).is_ok()
                && let Some(remote_static_ref) = hs.get_remote_static()
            {
                let remote_static = remote_static_ref.to_vec();
                if remote_static == pkt.from_key {
                    if let Some(peer) = manager.peers.iter_mut().find(|p| p.pubkey == remote_static) {
                        let mut resp_msg = vec![0u8; 128];
                        if let Ok(len) = hs.write_message(&[], &mut resp_msg) {
                            resp_msg.truncate(len);
                            if let Ok(stateless_transport) = hs.into_stateless_transport_mode() {
                                tracing::info!(
                                    "Handshake complete for peer {} (initiator) via relay. Transitioning to Transport mode.",
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

                                let mut resp_packet = Vec::with_capacity(1 + len);
                                resp_packet.push(0x02);
                                resp_packet.extend_from_slice(&resp_msg);

                                return Some(OutboundRelayPacket {
                                    dest_key: pkt.from_key,
                                    payload: resp_packet,
                                });
                            }
                        }
                    }
                }
            }
        }
    } else if packet_type == 0x02 {
        let mut manager = pm.lock().unwrap();
        let local_priv = manager.local_priv.clone();
        if let Some(peer) = manager.peers.iter_mut().find(|p| p.pubkey == pkt.from_key) {
            peer.handle_handshake_packet(&local_priv, packet_type, payload);
        }
    } else if packet_type == 0x03 {
        let decrypted = {
            let mut manager = pm.lock().unwrap();
            let mut result = None;
            if let Some(peer) = manager.peers.iter_mut().find(|p| p.pubkey == pkt.from_key) {
                if let Some(plaintext) = peer.decrypt_packet(payload) {
                    if let Some((src_ip, _dst_ip)) = parse_ipv4_header(&plaintext) {
                        if src_ip == peer.allowed_ip {
                            result = Some(plaintext);
                        } else {
                            tracing::warn!("Cryptokey routing check failed for relayed packet");
                        }
                    }
                }
            }
            result
        };

        if let Some(plaintext) = decrypted {
            if !plaintext.is_empty() {
                if let Err(e) = dev_tx.send(&plaintext).await {
                    tracing::error!("Failed to write relayed packet to TUN: {:?}", e);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // A PeerDescriptor whose pubkey is 32 copies of one byte.
    fn desc(byte: u8, allowed_ip: &str, endpoint: Option<&str>) -> PeerDescriptor {
        PeerDescriptor {
            public_key: format!("{byte:02x}").repeat(32),
            allowed_ip: allowed_ip.to_string(),
            endpoint: endpoint.map(str::to_string),
        }
    }

    #[test]
    fn sync_peers_adds_new_peers() {
        let mut pm = PeerManager::new(vec![0u8; 32], vec![]);
        pm.sync_peers(&[
            desc(0xaa, "10.0.99.2", Some("1.2.3.4:50001")),
            desc(0xbb, "10.0.99.3", None),
        ]);
        assert_eq!(pm.peers.len(), 2);
        assert_eq!(pm.peers[0].pubkey, vec![0xaa; 32]);
        assert_eq!(pm.peers[1].endpoint, None);
    }

    #[test]
    fn sync_peers_updates_endpoint_without_recreating_peer() {
        let mut pm = PeerManager::new(vec![0u8; 32], vec![]);
        pm.sync_peers(&[desc(0xaa, "10.0.99.2", None)]);
        let rx_before = pm.peers[0].last_rx;

        pm.sync_peers(&[desc(0xaa, "10.0.99.2", Some("9.9.9.9:9"))]);
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(pm.peers[0].endpoint, Some("9.9.9.9:9".parse().unwrap()));
        // Same Peer object (in-place update) => its session-tracking state
        // (here last_rx) is untouched; a recreate would have reset it.
        assert_eq!(pm.peers[0].last_rx, rx_before);
    }

    #[test]
    fn sync_peers_drops_absent_peers() {
        let mut pm = PeerManager::new(vec![0u8; 32], vec![]);
        pm.sync_peers(&[desc(0xaa, "10.0.99.2", None), desc(0xbb, "10.0.99.3", None)]);
        pm.sync_peers(&[desc(0xaa, "10.0.99.2", None)]);
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(pm.peers[0].pubkey, vec![0xaa; 32]);
    }

    #[test]
    fn sync_peers_skips_invalid_descriptor() {
        let mut pm = PeerManager::new(vec![0u8; 32], vec![]);
        let bad = PeerDescriptor {
            public_key: "zz".repeat(32), // not hex
            allowed_ip: "10.0.99.9".to_string(),
            endpoint: None,
        };
        pm.sync_peers(&[bad, desc(0xaa, "10.0.99.2", None)]);
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(pm.peers[0].pubkey, vec![0xaa; 32]);
    }

    #[tokio::test]
    async fn test_coordinator_registration_and_polling() {
        use axum::{routing::post, Router, Json, extract::State};
        use std::sync::{Arc, Mutex};
        use crate::coordinator::Registry;
        use crate::control::{RegisterRequest, RegisterResponse, PollRequest, PollResponse};

        let registry = Registry::new("10.0.99.0/24").unwrap();
        let state = Arc::new(Mutex::new(registry));

        let app = Router::new()
            .route("/register", post(|State(state): State<Arc<Mutex<Registry>>>, Json(req): Json<RegisterRequest>| async move {
                let mut reg = state.lock().unwrap();
                let (assigned_ip, observed_endpoint) = reg.register(&req.public_key, req.endpoint, req.hostname, None).unwrap();
                let peers = reg.peers_for(&req.public_key);
                Json(RegisterResponse { assigned_ip, peers, observed_endpoint })
            }))
            .route("/poll", post(|State(state): State<Arc<Mutex<Registry>>>, Json(req): Json<PollRequest>| async move {
                let mut reg = state.lock().unwrap();
                reg.poll(&req.public_key, req.endpoint, None).unwrap();
                let peers = reg.peers_for(&req.public_key);
                Json(PollResponse { peers })
            }))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let server_url = format!("http://{}", local_addr);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();

        // 1. Register Node A
        let reg_req_a = RegisterRequest {
            public_key: "aa".repeat(32),
            auth_key: "secret".to_string(),
            endpoint: "1.1.1.1:50000".to_string(),
            hostname: Some("node-a".to_string()),
        };
        let resp_a: RegisterResponse = client
            .post(format!("{}/register", server_url))
            .json(&reg_req_a)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp_a.assigned_ip, "10.0.99.1");
        assert!(resp_a.peers.is_empty());

        // 2. Register Node B
        let reg_req_b = RegisterRequest {
            public_key: "bb".repeat(32),
            auth_key: "secret".to_string(),
            endpoint: "2.2.2.2:50000".to_string(),
            hostname: Some("node-b".to_string()),
        };
        let resp_b: RegisterResponse = client
            .post(format!("{}/register", server_url))
            .json(&reg_req_b)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp_b.assigned_ip, "10.0.99.2");
        assert_eq!(resp_b.peers.len(), 1);
        assert_eq!(resp_b.peers[0].public_key, "aa".repeat(32));

        // 3. Poll Node A - should now see Node B
        let poll_req_a = PollRequest {
            public_key: "aa".repeat(32),
            auth_key: "secret".to_string(),
            endpoint: "1.1.1.1:50000".to_string(),
        };
        let poll_resp_a: PollResponse = client
            .post(format!("{}/poll", server_url))
            .json(&poll_req_a)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(poll_resp_a.peers.len(), 1);
        assert_eq!(poll_resp_a.peers[0].public_key, "bb".repeat(32));
    }

    #[test]
    fn test_determine_dest_no_relay() {
        let peer = Peer::new(vec![0xbb; 32], Some("1.2.3.4:50002".parse().unwrap()), "10.0.99.2".parse().unwrap());

        // If has_relay is false, and endpoint is Some, it should return Udp(endpoint).
        let dest = peer.determine_dest(false);
        assert!(matches!(dest, Some(OutboundDest::Udp(_))));
        if let Some(OutboundDest::Udp(addr)) = dest {
            assert_eq!(addr, "1.2.3.4:50002".parse::<SocketAddr>().unwrap());
        }

        // If has_relay is false, and endpoint is None, it should return None.
        let peer_no_ep = Peer::new(vec![0xbb; 32], None, "10.0.99.2".parse().unwrap());
        let dest_no_ep = peer_no_ep.determine_dest(false);
        assert!(dest_no_ep.is_none());
    }

    #[test]
    fn test_determine_dest_with_relay_fallback() {
        let mut peer = Peer::new(vec![0xbb; 32], Some("1.2.3.4:50002".parse().unwrap()), "10.0.99.2".parse().unwrap());

        // Initially last_direct_rx is Instant::now(), so last_direct_rx.elapsed() < 10.
        // It should use direct UDP.
        let dest = peer.determine_dest(true);
        assert!(matches!(dest, Some(OutboundDest::Udp(_))));

        // If last_direct_rx is 11 seconds ago, it should fallback to Relay.
        peer.last_direct_rx = Instant::now() - std::time::Duration::from_secs(11);
        let dest_fallback = peer.determine_dest(true);
        assert!(matches!(dest_fallback, Some(OutboundDest::Relay(_))));
        if let Some(OutboundDest::Relay(key)) = dest_fallback {
            assert_eq!(key, [0xbb; 32]);
        }

        // If endpoint is None, it should always use Relay (if has_relay is true).
        let peer_no_ep = Peer::new(vec![0xbb; 32], None, "10.0.99.2".parse().unwrap());
        let dest_no_ep = peer_no_ep.determine_dest(true);
        assert!(matches!(dest_no_ep, Some(OutboundDest::Relay(_))));
    }

    #[tokio::test]
    async fn test_relay_fallback() {
        use axum::{routing::post, Router, Json, extract::State};
        use std::sync::{Arc, Mutex};
        use crate::coordinator::Registry;
        use crate::control::{RegisterRequest, RegisterResponse};
        use crate::relay::{RelayClient, OutboundRelayPacket};

        // 1. Mock Coordinator
        let registry = Registry::new("10.0.99.0/24").unwrap();
        let state = Arc::new(Mutex::new(registry));
        let app = Router::new()
            .route("/register", post(|State(state): State<Arc<Mutex<Registry>>>, Json(req): Json<RegisterRequest>| async move {
                let mut reg = state.lock().unwrap();
                let (assigned_ip, observed_endpoint) = reg.register(&req.public_key, req.endpoint, req.hostname, None).unwrap();
                let peers = reg.peers_for(&req.public_key);
                Json(RegisterResponse { assigned_ip, peers, observed_endpoint })
            }))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // 2. Mock Relay TCP Server
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap().to_string();

        let received_packets = Arc::new(Mutex::new(Vec::new()));
        let received_packets_clone = received_packets.clone();

        tokio::spawn(async move {
            let (mut stream, _) = relay_listener.accept().await.unwrap();
            // Read 32-byte identity
            let mut id = [0u8; 32];
            use tokio::io::AsyncReadExt;
            if stream.read_exact(&mut id).await.is_ok() {
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                    let mut frame = vec![0u8; frame_len];
                    if stream.read_exact(&mut frame).await.is_err() {
                        break;
                    }
                    let mut dest = [0u8; 32];
                    dest.copy_from_slice(&frame[..32]);
                    let payload = frame[32..].to_vec();
                    received_packets_clone.lock().unwrap().push((dest, payload));
                }
            }
        });

        // 3. Setup peer manager with a peer that has no direct endpoint (inbound only)
        // so it has to use the relay.
        let local_priv = vec![0x01; 32];
        let peer_pubkey = vec![0xbb; 32];

        // We set last_direct_rx to 11s ago to simulate fallback.
        let mut peer = Peer::new(peer_pubkey.clone(), None, "10.0.99.2".parse().unwrap());
        peer.last_direct_rx = Instant::now() - std::time::Duration::from_secs(11);

        let pm = Arc::new(std::sync::Mutex::new(PeerManager::new(local_priv, vec![peer])));

        // 4. Connect relay client and run tx_forward
        let local_pubkey_arr = [0xaa; 32];
        let client = RelayClient::new(relay_addr, local_pubkey_arr);
        let (relay_tx, _relay_rx, _connection_handle) = client.connect().await.unwrap();

        // 5. Test determine_dest and send action
        let action = {
            let mut manager = pm.lock().unwrap();
            let peer = &mut manager.peers[0];
            let packet = vec![0x03, 0x01, 0x02]; // dummy encrypted data
            let dest = peer.determine_dest(true).unwrap();
            (packet, dest)
        };

        // Match dest and send it via the relay channel
        match action.1 {
            OutboundDest::Relay(dest_key) => {
                relay_tx.send(OutboundRelayPacket { dest_key, payload: action.0 }).await.unwrap();
            }
            _ => panic!("Expected relay destination"),
        }

        // Give the background relay task a moment to process the frame
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let packets = received_packets.lock().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0, [0xbb; 32]);
        assert_eq!(packets[0].1, vec![0x03, 0x01, 0x02]);
    }
}

