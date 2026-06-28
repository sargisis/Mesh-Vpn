//! AraxMesh: a self-hosted, encrypted overlay-network (mesh VPN).
#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod coordinator;
pub mod daemon;
pub mod metrics;
pub mod peer;
pub mod session;
pub mod nat;
pub mod packet;
pub mod relay;
mod types;

pub use daemon::{DaemonStatus, PeerStatus, run, run_with_settings};
pub use types::PeerDescriptor;

/// Common error type for AraxMesh operations.
#[derive(thiserror::Error, Debug)]
pub enum AraxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Handshake error: {0}")]
    Handshake(String),

    #[error("Coordinator error: {0}")]
    Coordinator(String),

    #[error("Peer error: {0}")]
    Peer(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}
