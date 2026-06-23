//! AraxMesh data-plane daemon: peer/session state and the runtime loop.

use crate::config::{Startup, parse_peer_arg, parse_startup};
use crate::control::{PollRequest, PollResponse, RegisterRequest, RegisterResponse};
use crate::nat;
use rand::{Rng, RngCore};
use crate::packet::{parse_ipv4_header, parse_ipv4_total_length};
use crate::types::PeerDescriptor;
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tun_rs::DeviceBuilder;
use crate::relay::{OutboundRelayPacket, RelayedPacket, RelayClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MagicConfig {
    pub handshake_init: u8,
    pub handshake_resp: u8,
    pub data: u8,
    pub probe: u8,
}

impl MagicConfig {
    pub fn default() -> Self {
        Self {
            handshake_init: 0x01,
            handshake_resp: 0x02,
            data: 0x03,
            probe: 0x04,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerStatus {
    pub pubkey: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub last_rx_secs_ago: Option<u64>,
    pub last_tx_secs_ago: Option<u64>,
    pub is_active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonStatus {
    pub connection_state: String,
    pub assigned_ip: Option<String>,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub peers: Vec<PeerStatus>,
}


/// Exponential backoff for reconnect / retry loops: start small, double on each
/// failure up to a cap, and `reset` after a success. Keeps a flapping coordinator
/// or relay from being hammered while ensuring the daemon never gives up and dies.
struct Backoff {
    current: Duration,
    max: Duration,
}

impl Backoff {
    const INITIAL: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);

    fn new() -> Self {
        Self {
            current: Self::INITIAL,
            max: Self::MAX,
        }
    }

    fn reset(&mut self) {
        self.current = Self::INITIAL;
    }

    /// Return the current delay, then double it (saturating at `max`) for next time.
    fn advance(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * 2).min(self.max);
        delay
    }

    /// Sleep for the current delay, then advance.
    async fn wait(&mut self) {
        tokio::time::sleep(self.advance()).await;
    }
}

/// Sliding-window anti-replay filter (RFC 6479 / WireGuard style).
///
/// Each session carries one of these on the RX side. A nonce is accepted at most
/// once: duplicates and nonces older than the window are rejected. The window only
/// advances on *authenticated* packets — `check_and_update` is called after the AEAD
/// verifies, so a forged packet can never poison the window and starve real traffic.
struct ReplayWindow {
    /// Bitmap over the last `WINDOW_BITS` nonces, indexed `nonce % WINDOW_BITS`.
    bitmap: [u64; Self::BITMAP_WORDS],
    /// Highest nonce accepted so far.
    last: u64,
    /// False until the first packet is accepted (so nonce 0 is valid).
    initialized: bool,
}

impl ReplayWindow {
    const WINDOW_BITS: u64 = 1024;
    const BITMAP_WORDS: usize = (Self::WINDOW_BITS / 64) as usize;

    fn new() -> Self {
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
    fn check_and_update(&mut self, nonce: u64) -> bool {
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

struct ActiveSession {
    state: StatelessTransportState,
    tx_nonce: u64,
    established_at: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    replay: ReplayWindow,
}

#[derive(Debug, Clone)]
enum OutboundDest {
    Udp(SocketAddr),
    Relay([u8; 32]),
}

struct Peer {
    pubkey: Vec<u8>,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<crate::packet::Ipv4Subnet>,

    active: Option<ActiveSession>,
    previous: Option<ActiveSession>,
    handshake: Option<HandshakeState>,
    last_handshake_attempt: Option<Instant>,
    last_handshake_packet: Option<Vec<u8>>,

    last_rx: Instant,
    last_tx: Instant,
    last_direct_rx: Instant,
    magic: MagicConfig,
}

impl Peer {
    fn new(pubkey: Vec<u8>, endpoint: Option<SocketAddr>, allowed_ips: Vec<crate::packet::Ipv4Subnet>) -> Self {
        Self {
            pubkey,
            endpoint,
            allowed_ips,
            active: None,
            previous: None,
            handshake: None,
            last_handshake_attempt: None,
            last_handshake_packet: None,
            last_rx: Instant::now(),
            last_tx: Instant::now(),
            last_direct_rx: Instant::now(),
            magic: MagicConfig::default(),
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

                        use rand::RngCore;
                        let mut packet = Vec::with_capacity(1 + len + 64);
                        packet.push(self.magic.handshake_init);
                        packet.extend_from_slice(&msg);
                        let pad_len = rand::thread_rng().gen_range(0..=64);
                        let mut padding = vec![0u8; pad_len];
                        rand::thread_rng().fill_bytes(&mut padding);
                        packet.extend_from_slice(&padding);

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
        if packet_type == self.magic.handshake_init {
            let payload = &payload[..96.min(payload.len())];
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
                                        rx_bytes: 0,
                                        replay: ReplayWindow::new(),
                                    });
                                    self.last_rx = Instant::now();
                                    self.last_tx = Instant::now();

                                    use rand::RngCore;
                                    let mut resp_packet = Vec::with_capacity(1 + len + 64);
                                    resp_packet.push(self.magic.handshake_resp);
                                    resp_packet.extend_from_slice(&resp_msg);
                                    let pad_len = rand::thread_rng().gen_range(0..=64);
                                    let mut padding = vec![0u8; pad_len];
                                    rand::thread_rng().fill_bytes(&mut padding);
                                    resp_packet.extend_from_slice(&padding);
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
        } else if packet_type == self.magic.handshake_resp {
            let payload = &payload[..48.min(payload.len())];
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
                            rx_bytes: 0,
                            replay: ReplayWindow::new(),
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
        } else {
            None
        }
    }

    fn encrypt_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let active = self.active.as_mut()?;
        let nonce = active.tx_nonce;
        active.tx_nonce += 1;
        active.tx_bytes += payload.len() as u64;

        let mut padded_payload = payload.to_vec();
        if !payload.is_empty() && parse_ipv4_total_length(payload).is_some() {
            let pad_len = rand::thread_rng().gen_range(0..=128);
            let mut padding = vec![0u8; pad_len];
            rand::thread_rng().fill_bytes(&mut padding);
            padded_payload.extend_from_slice(&padding);
        }

        let mut ciphertext = vec![0u8; padded_payload.len() + 16];
        match active.state.write_message(nonce, &padded_payload, &mut ciphertext) {
            Ok(len) => {
                ciphertext.truncate(len);
                self.last_tx = Instant::now();

                let mut packet = Vec::with_capacity(1 + 8 + ciphertext.len());
                packet.push(self.magic.data);
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

        if let Some(active) = self.active.as_mut()
            && let Ok(len) = active.state.read_message(nonce, ciphertext, &mut plaintext)
        {
            if !active.replay.check_and_update(nonce) {
                tracing::debug!("Dropping replayed/too-old packet, nonce {}", nonce);
                return None;
            }
            active.rx_bytes += payload.len() as u64;
            plaintext.truncate(len);
            if !plaintext.is_empty() {
                if let Some(total_len) = parse_ipv4_total_length(&plaintext) {
                    if total_len <= plaintext.len() {
                        plaintext.truncate(total_len);
                    }
                }
            }
            self.last_rx = Instant::now();
            return Some(plaintext);
        }

        if let Some(prev) = self.previous.as_mut()
            && prev.established_at.elapsed().as_secs() < 15
            && let Ok(len) = prev.state.read_message(nonce, ciphertext, &mut plaintext)
        {
            if !prev.replay.check_and_update(nonce) {
                tracing::debug!("Dropping replayed/too-old packet, nonce {} (previous session)", nonce);
                return None;
            }
            prev.rx_bytes += payload.len() as u64;
            plaintext.truncate(len);
            if !plaintext.is_empty() {
                if let Some(total_len) = parse_ipv4_total_length(&plaintext) {
                    if total_len <= plaintext.len() {
                        plaintext.truncate(total_len);
                    }
                }
            }
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
    magic: MagicConfig,
}

impl PeerManager {
    fn new(local_priv: Vec<u8>, mut peers: Vec<Peer>, magic: MagicConfig) -> Self {
        for peer in &mut peers {
            peer.magic = magic;
        }
        Self { local_priv, peers, magic }
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
                existing.allowed_ips = w.allowed_ips;
            } else {
                if let Some(ep) = w.endpoint {
                    new_endpoints.push(ep);
                    let mut p = Peer::new(w.pubkey, Some(ep), w.allowed_ips.clone());
                    p.magic = self.magic;
                    self.peers.push(p);
                } else {
                    let mut p = Peer::new(w.pubkey, None, w.allowed_ips.clone());
                    p.magic = self.magic;
                    self.peers.push(p);
                }
            }
        }
        new_endpoints
    }

    fn find_best_peer_idx(&self, dst_ip: std::net::Ipv4Addr) -> Option<usize> {
        let mut matched_peer_idx = None;
        let mut best_prefix_len = -1i32;

        for (idx, peer) in self.peers.iter().enumerate() {
            for subnet in &peer.allowed_ips {
                if subnet.contains(dst_ip) {
                    let len = subnet.prefix_len as i32;
                    if len > best_prefix_len {
                        best_prefix_len = len;
                        matched_peer_idx = Some(idx);
                    }
                }
            }
        }
        matched_peer_idx
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

    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    run_with_settings(settings, shutdown_rx, None).await
}

pub async fn run_with_settings(
    settings: crate::config::DaemonSettings,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    status_tx: Option<tokio::sync::mpsc::Sender<DaemonStatus>>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        // Retry forever with backoff: a coordinator that is down at startup must not
        // kill the daemon — keep trying until it answers.
        let reg_resp: RegisterResponse = {
            let mut backoff = Backoff::new();
            loop {
                match http_client.post(&reg_url).json(&reg_req).send().await {
                    Ok(resp) => match resp.json::<RegisterResponse>().await {
                        Ok(parsed) => break parsed,
                        Err(e) => {
                            tracing::warn!("Invalid registration response: {}; retrying...", e)
                        }
                    },
                    Err(e) => tracing::warn!(
                        "Registration failed: {}; coordinator may be unreachable, retrying...",
                        e
                    ),
                }
                backoff.wait().await;
            }
        };

        tracing::info!("Successfully registered. Assigned IP: {}", reg_resp.assigned_ip);
        if let Some(ref obs) = reg_resp.observed_endpoint {
            tracing::info!("Observed external endpoint (STUN-like): {}", obs);
        }

        let mut parsed_peers = Vec::new();
        for p_desc in reg_resp.peers {
            match parse_peer_arg(&p_desc.to_spec()) {
                Ok(parsed) => {
                    parsed_peers.push(Peer::new(parsed.pubkey, parsed.endpoint, parsed.allowed_ips));
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
            parsed_peers.push(Peer::new(parsed.pubkey, parsed.endpoint, parsed.allowed_ips));
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
        let allowed_ips_str = peer.allowed_ips.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            "Configured Peer: allowed_ips={}, pubkey={}, endpoint={:?}",
            allowed_ips_str,
            hex::encode(&peer.pubkey),
            peer.endpoint
        );
    }

    let magic_config = MagicConfig {
        handshake_init: settings.magic_handshake_init,
        handshake_resp: settings.magic_handshake_resp,
        data: settings.magic_data,
        probe: settings.magic_probe,
    };

    let pm = Arc::new(std::sync::Mutex::new(PeerManager::new(local_priv, peers, magic_config)));

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
    let status_tx_timer = status_tx.clone();
    let tun_ip_timer = tun_ip.clone();
    let timer_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;

            let mut actions = Vec::new();
            let mut status_to_send = None;
            {
                let mut manager = session_timer.lock().unwrap();
                let local_priv = manager.local_priv.clone();

                if status_tx_timer.is_some() {
                    let mut peer_statuses = Vec::new();
                    let mut total_uploaded = 0u64;
                    let mut total_downloaded = 0u64;

                    for peer in &manager.peers {
                        let is_active = peer.active.is_some();
                        let tx_bytes = peer.active.as_ref().map_or(0, |s| s.tx_bytes)
                            + peer.previous.as_ref().map_or(0, |s| s.tx_bytes);
                        let rx_bytes = peer.active.as_ref().map_or(0, |s| s.rx_bytes)
                            + peer.previous.as_ref().map_or(0, |s| s.rx_bytes);

                        total_uploaded += tx_bytes;
                        total_downloaded += rx_bytes;

                        let last_rx_secs_ago = peer.active.as_ref().map(|s| s.established_at.elapsed().as_secs());
                        let last_tx_secs_ago = peer.active.as_ref().map(|s| s.established_at.elapsed().as_secs());

                        peer_statuses.push(PeerStatus {
                            pubkey: hex::encode(&peer.pubkey),
                            endpoint: peer.endpoint.map(|e| e.to_string()),
                            allowed_ips: peer.allowed_ips.iter().map(|s| s.to_string()).collect(),
                            last_rx_secs_ago,
                            last_tx_secs_ago,
                            is_active,
                        });
                    }

                    let connection_state = if manager.peers.iter().any(|p| p.active.is_some()) {
                        "Connected".to_string()
                    } else {
                        "Connecting".to_string()
                    };

                    status_to_send = Some(DaemonStatus {
                        connection_state,
                        assigned_ip: Some(tun_ip_timer.clone()),
                        total_uploaded,
                        total_downloaded,
                        peers: peer_statuses,
                    });
                }

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

            if let Some(status) = status_to_send {
                if let Some(ref tx) = status_tx_timer {
                    let _ = tx.send(status).await;
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

                            let matched_peer_idx = manager.find_best_peer_idx(dst_ip);

                            if let Some(idx) = matched_peer_idx {
                                let peer = &mut manager.peers[idx];
                                if let Some(packet) = peer.encrypt_packet(packet_payload) {
                                    if let Some(dest) = peer.determine_dest(has_relay) {
                                        action = Some((packet, dest));
                                    }
                                } else if peer.active.is_none()
                                    && peer.handshake.is_none()
                                    && let Some(hs_packet) = peer.initiate_handshake(&local_priv)
                                {
                                    let allowed_ips_str = peer.allowed_ips.iter()
                                        .map(|s| s.to_string())
                                        .collect::<Vec<_>>()
                                        .join(",");
                                    tracing::info!(
                                        "Triggering handshake for peer {} at allowed IPs {}",
                                        hex::encode(&peer.pubkey),
                                        allowed_ips_str
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

                    let (magic_init, magic_resp, magic_data, magic_probe) = {
                        let manager = pm_rx.lock().unwrap();
                        (manager.magic.handshake_init, manager.magic.handshake_resp, manager.magic.data, manager.magic.probe)
                    };

                    let packet_type = buf[0];
                    let payload = &buf[1..n];

                    if packet_type == magic_init {
                        let resp = {
                            let mut manager = pm_rx.lock().unwrap();
                            let local_priv = manager.local_priv.clone();
                            let magic = manager.magic;
                            let mut response_packet = None;

                            let mut builder =
                                Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
                            builder = builder.local_private_key(&local_priv);

                            if let Ok(mut hs) = builder.build_responder() {
                                let mut read_buf = vec![0u8; 128];
                                let initiation_payload = &payload[..96.min(payload.len())];
                                if hs.read_message(initiation_payload, &mut read_buf).is_ok()
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
                                                    rx_bytes: 0,
                                                    replay: ReplayWindow::new(),
                                                });
                                                peer.last_rx = Instant::now();
                                                peer.last_tx = Instant::now();

                                                use rand::RngCore;
                                                let mut resp_packet = Vec::with_capacity(1 + len + 64);
                                                resp_packet.push(magic.handshake_resp);
                                                resp_packet.extend_from_slice(&resp_msg);
                                                let pad_len = rand::thread_rng().gen_range(0..=64);
                                                let mut padding = vec![0u8; pad_len];
                                                rand::thread_rng().fill_bytes(&mut padding);
                                                resp_packet.extend_from_slice(&padding);
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
                    } else if packet_type == magic_resp {
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
                    } else if packet_type == magic_data {
                        let decrypted = {
                            let mut manager = pm_rx.lock().unwrap();
                            let mut result = None;

                            // 1. Try by endpoint lookup
                            if let Some(peer) =
                                manager.peers.iter_mut().find(|p| p.endpoint == Some(addr))
                                && let Some(plaintext) = peer.decrypt_packet(payload)
                                && let Some((src_ip, _dst_ip)) = parse_ipv4_header(&plaintext)
                            {
                                if peer.allowed_ips.iter().any(|s| s.contains(src_ip)) {
                                    peer.last_direct_rx = Instant::now();
                                    result = Some(plaintext);
                                } else {
                                    let allowed_ips_str = peer.allowed_ips.iter()
                                        .map(|s| s.to_string())
                                        .collect::<Vec<_>>()
                                        .join(",");
                                    tracing::warn!(
                                        "Cryptokey routing check failed: src_ip {} does not match peer's allowed IPs {}",
                                        src_ip,
                                        allowed_ips_str
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
                                        && peer.allowed_ips.iter().any(|s| s.contains(src_ip))
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
                    } else if packet_type == magic_probe {
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
                                let (new_endpoints, probe_byte) = {
                                    let mut manager = pm_poll.lock().unwrap();
                                    (manager.sync_peers(&poll_resp.peers), manager.magic.probe)
                                };
                                // Punch holes for any newly discovered peers.
                                for ep in new_endpoints {
                                    tracing::info!("New peer discovered at {}; initiating hole punch", ep);
                                    let s = sock_poll.clone();
                                    tokio::spawn(async move {
                                        nat::punch_hole(&s, ep, probe_byte).await;
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
            let mut backoff = Backoff::new();
            loop {
                tracing::info!("Connecting to relay server at {}...", relay_addr);
                let client = RelayClient::new(relay_addr.clone(), local_pubkey);
                match client.connect().await {
                    Ok((relay_client_tx, mut relay_client_rx, connection_handle)) => {
                        // Connected: reset backoff so a later drop reconnects promptly.
                        backoff.reset();
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

                backoff.wait().await;
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
        _ = &mut shutdown_rx => {
            tracing::info!("Shutdown signal received; stopping daemon tasks");
        }
    }

    Ok(())
}

async fn process_relayed_packet(
    pm: &Arc<std::sync::Mutex<PeerManager>>,
    dev_tx: &Arc<tun_rs::AsyncDevice>,
    pkt: RelayedPacket,
) -> Option<OutboundRelayPacket> {
    let (packet_type, magic) = {
        let manager = pm.lock().unwrap();
        if pkt.payload.is_empty() {
            return None;
        }
        (pkt.payload[0], manager.magic)
    };
    let payload = &pkt.payload[1..];

    if packet_type == magic.handshake_init {
        let mut manager = pm.lock().unwrap();
        let local_priv = manager.local_priv.clone();

        let mut builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        builder = builder.local_private_key(&local_priv);

        if let Ok(mut hs) = builder.build_responder() {
            let mut read_buf = vec![0u8; 128];
            let initiation_payload = &payload[..96.min(payload.len())];
            if hs.read_message(initiation_payload, &mut read_buf).is_ok()
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
                                    rx_bytes: 0,
                                    replay: ReplayWindow::new(),
                                });
                                peer.last_rx = Instant::now();
                                peer.last_tx = Instant::now();

                                use rand::RngCore;
                                let mut resp_packet = Vec::with_capacity(1 + len + 64);
                                resp_packet.push(magic.handshake_resp);
                                resp_packet.extend_from_slice(&resp_msg);
                                let pad_len = rand::thread_rng().gen_range(0..=64);
                                let mut padding = vec![0u8; pad_len];
                                rand::thread_rng().fill_bytes(&mut padding);
                                resp_packet.extend_from_slice(&padding);

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
    } else if packet_type == magic.handshake_resp {
        let mut manager = pm.lock().unwrap();
        let local_priv = manager.local_priv.clone();
        if let Some(peer) = manager.peers.iter_mut().find(|p| p.pubkey == pkt.from_key) {
            peer.handle_handshake_packet(&local_priv, packet_type, payload);
        }
    } else if packet_type == magic.data {
        let decrypted = {
            let mut manager = pm.lock().unwrap();
            let mut result = None;
            if let Some(peer) = manager.peers.iter_mut().find(|p| p.pubkey == pkt.from_key) {
                if let Some(plaintext) = peer.decrypt_packet(payload) {
                    if let Some((src_ip, _dst_ip)) = parse_ipv4_header(&plaintext) {
                        if peer.allowed_ips.iter().any(|s| s.contains(src_ip)) {
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
        let mut pm = PeerManager::new(vec![0u8; 32], vec![], MagicConfig::default());
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
        let mut pm = PeerManager::new(vec![0u8; 32], vec![], MagicConfig::default());
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
        let mut pm = PeerManager::new(vec![0u8; 32], vec![], MagicConfig::default());
        pm.sync_peers(&[desc(0xaa, "10.0.99.2", None), desc(0xbb, "10.0.99.3", None)]);
        pm.sync_peers(&[desc(0xaa, "10.0.99.2", None)]);
        assert_eq!(pm.peers.len(), 1);
        assert_eq!(pm.peers[0].pubkey, vec![0xaa; 32]);
    }

    #[test]
    fn sync_peers_skips_invalid_descriptor() {
        let mut pm = PeerManager::new(vec![0u8; 32], vec![], MagicConfig::default());
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
        let peer = Peer::new(vec![0xbb; 32], Some("1.2.3.4:50002".parse().unwrap()), vec!["10.0.99.2".parse().unwrap()]);

        // If has_relay is false, and endpoint is Some, it should return Udp(endpoint).
        let dest = peer.determine_dest(false);
        assert!(matches!(dest, Some(OutboundDest::Udp(_))));
        if let Some(OutboundDest::Udp(addr)) = dest {
            assert_eq!(addr, "1.2.3.4:50002".parse::<SocketAddr>().unwrap());
        }

        // If has_relay is false, and endpoint is None, it should return None.
        let peer_no_ep = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.2".parse().unwrap()]);
        let dest_no_ep = peer_no_ep.determine_dest(false);
        assert!(dest_no_ep.is_none());
    }

    #[test]
    fn test_determine_dest_with_relay_fallback() {
        let mut peer = Peer::new(vec![0xbb; 32], Some("1.2.3.4:50002".parse().unwrap()), vec!["10.0.99.2".parse().unwrap()]);

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
        let peer_no_ep = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.2".parse().unwrap()]);
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
        let mut peer = Peer::new(peer_pubkey.clone(), None, vec!["10.0.99.2".parse().unwrap()]);
        peer.last_direct_rx = Instant::now() - std::time::Duration::from_secs(11);

        let pm = Arc::new(std::sync::Mutex::new(PeerManager::new(local_priv, vec![peer], MagicConfig::default())));

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

    #[test]
    fn test_longest_prefix_match() {
        use std::net::Ipv4Addr;

        // Peer A: 10.0.99.5/32 (specific host route)
        // Peer B: 10.0.99.0/24 (general subnet route)
        // Peer C: 0.0.0.0/0 (default exit node)
        let peer_a = Peer::new(vec![0xaa; 32], None, vec!["10.0.99.5/32".parse().unwrap()]);
        let peer_b = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.0/24".parse().unwrap()]);
        let peer_c = Peer::new(vec![0xcc; 32], None, vec!["0.0.0.0/0".parse().unwrap()]);

        let pm = PeerManager::new(vec![0x00; 32], vec![peer_a, peer_b, peer_c], MagicConfig::default());

        // 1. Matches A (specific host wins over /24 and /0)
        let ip_a: Ipv4Addr = "10.0.99.5".parse().unwrap();
        let idx_a = pm.find_best_peer_idx(ip_a).unwrap();
        assert_eq!(pm.peers[idx_a].pubkey, vec![0xaa; 32]);

        // 2. Matches B (subnet wins over /0)
        let ip_b: Ipv4Addr = "10.0.99.10".parse().unwrap();
        let idx_b = pm.find_best_peer_idx(ip_b).unwrap();
        assert_eq!(pm.peers[idx_b].pubkey, vec![0xbb; 32]);

        // 3. Matches C (exit node wins for any other IP)
        let ip_c: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let idx_c = pm.find_best_peer_idx(ip_c).unwrap();
        assert_eq!(pm.peers[idx_c].pubkey, vec![0xcc; 32]);

        // 4. If no exit node, and IP doesn't match subnets, returns None
        let peer_a_no_c = Peer::new(vec![0xaa; 32], None, vec!["10.0.99.5/32".parse().unwrap()]);
        let peer_b_no_c = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.0/24".parse().unwrap()]);
        let pm_no_c = PeerManager::new(vec![0x00; 32], vec![peer_a_no_c, peer_b_no_c], MagicConfig::default());
        assert!(pm_no_c.find_best_peer_idx("8.8.8.8".parse().unwrap()).is_none());
    }

    // --- Gate 6.0: anti-replay -------------------------------------------------

    /// Run an NN Noise handshake (no static keys needed for a transport-layer test)
    /// and return the two ends in stateless transport mode.
    fn make_transport_pair() -> (StatelessTransportState, StatelessTransportState) {
        let mut initiator = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .build_initiator()
            .unwrap();
        let mut responder = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .build_responder()
            .unwrap();

        let mut buf = [0u8; 1024];
        let mut buf2 = [0u8; 1024];

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder.read_message(&buf[..len], &mut buf2).unwrap();

        let len = responder.write_message(&[], &mut buf2).unwrap();
        initiator.read_message(&buf2[..len], &mut buf).unwrap();

        (
            initiator.into_stateless_transport_mode().unwrap(),
            responder.into_stateless_transport_mode().unwrap(),
        )
    }

    fn session(state: StatelessTransportState) -> ActiveSession {
        ActiveSession {
            state,
            tx_nonce: 0,
            established_at: Instant::now(),
            tx_bytes: 0,
            rx_bytes: 0,
            replay: ReplayWindow::new(),
        }
    }

    #[test]
    fn replay_window_accepts_in_order_rejects_duplicates_and_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0), "first nonce accepted");
        assert!(!w.check_and_update(0), "duplicate of 0 rejected");
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(5), "jump forward accepted");
        assert!(w.check_and_update(4), "in-window, unseen accepted");
        assert!(!w.check_and_update(5), "duplicate of 5 rejected");

        // Advance far past the window; the whole bitmap clears.
        assert!(w.check_and_update(5000));
        assert!(!w.check_and_update(1), "nonce far behind the window is too old");
        assert!(w.check_and_update(5000 - 10), "still inside the window");
    }

    /// The core Gate 6.0 guarantee: a captured-and-resent valid packet is rejected.
    #[test]
    fn replayed_data_packet_is_rejected() {
        let (init_ts, resp_ts) = make_transport_pair();
        let mut sender = Peer::new(vec![0xaa; 32], None, vec!["10.0.99.1/32".parse().unwrap()]);
        sender.active = Some(session(init_ts));
        let mut receiver = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.2/32".parse().unwrap()]);
        receiver.active = Some(session(resp_ts));

        let plaintext = b"hello araxmesh";
        let wire = sender.encrypt_packet(plaintext).expect("encrypt");
        assert_eq!(wire[0], 0x03, "transport-data type byte");
        let payload = &wire[1..]; // strip type byte, as the udp_to_tun dispatch does

        let first = receiver.decrypt_packet(payload).expect("first delivery decrypts");
        assert_eq!(first, plaintext);

        // Replaying the identical wire bytes must be dropped by the anti-replay window.
        assert!(
            receiver.decrypt_packet(payload).is_none(),
            "replayed packet must be rejected"
        );
    }

    #[test]
    fn reordered_packets_within_window_are_accepted_once() {
        let (init_ts, resp_ts) = make_transport_pair();
        let mut sender = Peer::new(vec![0xaa; 32], None, vec!["10.0.99.1/32".parse().unwrap()]);
        sender.active = Some(session(init_ts));
        let mut receiver = Peer::new(vec![0xbb; 32], None, vec!["10.0.99.2/32".parse().unwrap()]);
        receiver.active = Some(session(resp_ts));

        // Encrypt three packets (nonces 0, 1, 2).
        let p0 = sender.encrypt_packet(b"zero").unwrap();
        let p1 = sender.encrypt_packet(b"one").unwrap();
        let p2 = sender.encrypt_packet(b"two").unwrap();

        // Deliver out of order: 2, 0, 1 — each accepted exactly once.
        assert!(receiver.decrypt_packet(&p2[1..]).is_some());
        assert!(receiver.decrypt_packet(&p0[1..]).is_some());
        assert!(receiver.decrypt_packet(&p1[1..]).is_some());

        // Re-delivering any of them is a replay.
        assert!(receiver.decrypt_packet(&p1[1..]).is_none());
        assert!(receiver.decrypt_packet(&p2[1..]).is_none());
    }

    #[test]
    fn backoff_doubles_caps_and_resets() {
        let mut b = Backoff::new();
        assert_eq!(b.advance(), Duration::from_secs(1));
        assert_eq!(b.advance(), Duration::from_secs(2));
        assert_eq!(b.advance(), Duration::from_secs(4));
        assert_eq!(b.advance(), Duration::from_secs(8));
        assert_eq!(b.advance(), Duration::from_secs(16));
        assert_eq!(b.advance(), Duration::from_secs(30), "capped at MAX (32 -> 30)");
        assert_eq!(b.advance(), Duration::from_secs(30), "stays capped");
        b.reset();
        assert_eq!(b.advance(), Duration::from_secs(1), "reset returns to INITIAL");
    }

    #[test]
    fn test_obfuscation_and_padding_transmission() {
        let magic = MagicConfig {
            handshake_init: 0x5e,
            handshake_resp: 0xbc,
            data: 0x8a,
            probe: 0x22,
        };

        // 1. Handshake Simulation
        let builder_sender = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let sender_keys = builder_sender.generate_keypair().unwrap();
        let builder_receiver = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let receiver_keys = builder_receiver.generate_keypair().unwrap();

        let mut sender = Peer::new(receiver_keys.public.clone(), None, vec!["10.0.99.2/32".parse().unwrap()]);
        sender.magic = magic;

        let mut receiver = Peer::new(sender_keys.public.clone(), None, vec!["10.0.99.1/32".parse().unwrap()]);
        receiver.magic = magic;

        // Initiate handshake on sender
        let handshake_init_packet = sender.initiate_handshake(&sender_keys.private).expect("initiate handshake");
        assert_eq!(handshake_init_packet[0], magic.handshake_init);
        // The packet length should be at least 1 (type) + 96 (Noise IK handshake msg) = 97 bytes, and potentially up to 97 + 64 = 161 bytes due to padding.
        assert!(handshake_init_packet.len() >= 97);
        assert!(handshake_init_packet.len() <= 161);

        // Receive handshake initiation on receiver
        let handshake_init_type = handshake_init_packet[0];
        let handshake_init_payload = &handshake_init_packet[1..];
        let handshake_resp_packet = receiver.handle_handshake_packet(
            &receiver_keys.private,
            handshake_init_type,
            handshake_init_payload,
        ).expect("handle handshake initiation and build response");

        assert_eq!(handshake_resp_packet[0], magic.handshake_resp);
        // Length should be at least 1 (type) + 48 (Noise IK response msg) = 49 bytes, and up to 49 + 64 = 113 bytes due to padding.
        assert!(handshake_resp_packet.len() >= 49);
        assert!(handshake_resp_packet.len() <= 113);

        // Receive handshake response on sender
        let handshake_resp_type = handshake_resp_packet[0];
        let handshake_resp_payload = &handshake_resp_packet[1..];
        let none_resp = sender.handle_handshake_packet(
            &sender_keys.private,
            handshake_resp_type,
            handshake_resp_payload,
        );
        assert!(none_resp.is_none(), "responder handshake finishes handshakes and returns None");

        // Both sender and receiver should now have active sessions in transport mode
        assert!(sender.active.is_some());
        assert!(receiver.active.is_some());

        // 2. Data Transmission Simulation (with padding/obfuscation)
        // A mock IPv4 packet (40 bytes total length: 20-byte header + 20-byte payload)
        let mut mock_ipv4_packet = vec![0u8; 40];
        mock_ipv4_packet[0] = 0x45; // Version 4, IHL 5
        // Total length is 40 (0x0028)
        mock_ipv4_packet[2] = 0x00;
        mock_ipv4_packet[3] = 0x28;
        // Src IP 10.0.99.1, Dst IP 10.0.99.2
        mock_ipv4_packet[12..16].copy_from_slice(&[10, 0, 99, 1]);
        mock_ipv4_packet[16..20].copy_from_slice(&[10, 0, 99, 2]);
        // Fill the rest with dummy payload data
        for i in 20..40 {
            mock_ipv4_packet[i] = i as u8;
        }

        // Encrypt on sender
        let encrypted_packet = sender.encrypt_packet(&mock_ipv4_packet).expect("encrypt packet");
        assert_eq!(encrypted_packet[0], magic.data);
        // Size should be: 1 (type) + 8 (nonce) + 40 (plaintext) + padding (0 to 128) + 16 (tag)
        // Min size: 1 + 8 + 40 + 0 + 16 = 65
        // Max size: 1 + 8 + 40 + 128 + 16 = 193
        assert!(encrypted_packet.len() >= 65);
        assert!(encrypted_packet.len() <= 193);

        // Decrypt on receiver
        let decrypted_payload = &encrypted_packet[1..]; // strip type byte only, keep 8-byte nonce
        let decrypted_plaintext = receiver.decrypt_packet(decrypted_payload).expect("decrypt packet");
        // Verify length is truncated exactly to original 40 bytes despite random padding
        assert_eq!(decrypted_plaintext.len(), 40);
        assert_eq!(decrypted_plaintext, mock_ipv4_packet);
    }
}

