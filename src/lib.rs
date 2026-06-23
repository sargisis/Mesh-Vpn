//! AraxMesh: a self-hosted, encrypted overlay-network (mesh VPN).
#![forbid(unsafe_code)]

mod config;
pub mod control;
pub mod coordinator;
pub mod daemon;
mod packet;
mod types;

pub use daemon::run;
pub use types::PeerDescriptor;
