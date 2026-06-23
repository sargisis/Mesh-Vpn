//! AraxMesh: a self-hosted, encrypted overlay-network (mesh VPN).
#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod coordinator;
pub mod daemon;
pub mod nat;
pub mod packet;
pub mod relay;
mod types;

pub use daemon::{run, run_with_settings, DaemonStatus, PeerStatus};
pub use types::PeerDescriptor;
