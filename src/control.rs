//! Control-plane wire models shared by the coordinator and the daemon's
//! coordinator client. Plain JSON over HTTP (Phase 3, pre-auth-key model).

use crate::types::PeerDescriptor;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A node joining the network. `auth_key` is the shared pre-auth secret; the
/// node identifies itself by its Noise static public key and advertises the
/// UDP `endpoint` other peers should dial it on.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct RegisterRequest {
    pub public_key: String,
    pub auth_key: String,
    pub endpoint: String,
    #[serde(default)]
    pub hostname: Option<String>,
}

/// The coordinator's reply: the overlay IP assigned to this node (stable across
/// re-registration) and the current table of every other node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub assigned_ip: String,
    pub peers: Vec<PeerDescriptor>,
    /// The external `ip:port` of the registering node as observed by the
    /// coordinator from the TCP connection (STUN-like reflexive address).
    #[serde(default)]
    pub observed_endpoint: Option<String>,
}

/// A periodic refresh from an already-registered node. Re-advertises the
/// endpoint (it may have changed) and pulls the latest peer table.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct PollRequest {
    pub public_key: String,
    pub auth_key: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub peers: Vec<PeerDescriptor>,
}
