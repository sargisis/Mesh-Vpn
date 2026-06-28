use std::net::SocketAddr;
use std::time::Instant;
use snow::{Builder, HandshakeState};
use rand::{Rng, RngCore};
use crate::daemon::{MagicConfig, OutboundDest};
use crate::session::{ActiveSession, ReplayWindow};
use crate::packet::parse_ipv4_total_length;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveKey(pub [u8; 32]);

pub struct Peer {
    pub pubkey: Vec<u8>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<crate::packet::Ipv4Subnet>,

    pub active: Option<ActiveSession>,
    pub previous: Option<ActiveSession>,
    pub handshake: Option<HandshakeState>,
    pub last_handshake_attempt: Option<Instant>,
    pub last_handshake_packet: Option<Vec<u8>>,

    pub last_rx: Instant,
    pub last_tx: Instant,
    pub last_direct_rx: Instant,
    pub magic: MagicConfig,
}

impl Peer {
    pub fn new(
        pubkey: Vec<u8>,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<crate::packet::Ipv4Subnet>,
    ) -> Self {
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

    pub fn determine_dest(&self, has_relay: bool) -> Option<OutboundDest> {
        if has_relay && (self.endpoint.is_none() || self.last_direct_rx.elapsed().as_secs() >= 10) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&self.pubkey);
            Some(OutboundDest::Relay(key))
        } else {
            self.endpoint.map(OutboundDest::Udp)
        }
    }

    pub fn initiate_handshake(&mut self, local_priv: &[u8]) -> Option<Vec<u8>> {
        let mut builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        builder = builder.local_private_key(local_priv);
        builder = builder.remote_public_key(&self.pubkey);

        match builder.build_initiator() {
            Ok(mut hs) => {
                let mut msg = vec![0u8; 128];
                match hs.write_message(&[], &mut msg) {
                    Ok(len) => {
                        msg.truncate(len);

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

    pub fn handle_handshake_packet(
        &mut self,
        local_priv: &[u8],
        packet_type: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if packet_type == self.magic.handshake_init {
            let payload = &payload[..96.min(payload.len())];
            let mut builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
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

    pub fn encrypt_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
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
        match active
            .state
            .write_message(nonce, &padded_payload, &mut ciphertext)
        {
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

    pub fn decrypt_packet(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
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

        if let Some(active) = self.active.as_mut() {
            if let Ok(len) = active.state.read_message(nonce, ciphertext, &mut plaintext) {
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
        }

        if let Some(prev) = self.previous.as_mut() {
            if prev.established_at.elapsed().as_secs() < 15 {
                if let Ok(len) = prev.state.read_message(nonce, ciphertext, &mut plaintext) {
                    if !prev.replay.check_and_update(nonce) {
                        tracing::debug!(
                            "Dropping replayed/too-old packet, nonce {} (previous session)",
                            nonce
                        );
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
            }
        }

        None
    }

    pub fn check_rotation(&mut self) -> bool {
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

pub struct PeerManager {
    pub local_priv: Vec<u8>,
    pub peers: Vec<Peer>,
    pub magic: MagicConfig,
}

impl PeerManager {
    pub fn new(local_priv: Vec<u8>, mut peers: Vec<Peer>, magic: MagicConfig) -> Self {
        for peer in &mut peers {
            peer.magic = magic;
        }
        Self {
            local_priv,
            peers,
            magic,
        }
    }

    /// Reconcile the peer table with the set advertised by the coordinator:
    /// add peers we don't have, update the endpoint/allowed_ip of ones we do
    /// (keeping their live Noise sessions rather than tearing them down), and
    /// drop peers the coordinator no longer lists. Malformed descriptors are
    /// logged and skipped — a bad control-plane entry must not abort the sync.
    ///
    /// Returns the endpoints of newly added peers (for hole-punching).
    pub fn sync_peers(&mut self, descriptors: &[crate::types::PeerDescriptor]) -> Vec<std::net::SocketAddr> {
        let mut wanted = Vec::new();
        for d in descriptors {
            match crate::config::parse_peer_arg(&d.to_spec()) {
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

    pub fn find_best_peer_idx(&self, dst_ip: std::net::Ipv4Addr) -> Option<usize> {
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
