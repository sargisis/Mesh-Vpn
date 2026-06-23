//! Shared control-plane types used by both the daemon and the coordinator.
// (coordinator). Keeping them in one library crate lets both binaries agree on
// the wire shape of a peer without duplicating it.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// One peer as described by config or advertised by the coordinator.
///
/// Fields are kept as strings so a single validation path (`parse_peer_arg` in
/// the daemon) parses peers from the TOML config, the `--peer` CLI flag, and
/// the coordinator API identically. `endpoint` is `None` for a peer that only
/// ever connects inbound (we never dial it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDescriptor {
    pub public_key: String,
    pub allowed_ip: String,
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl PeerDescriptor {
    /// Render to the daemon's `pubkey;[endpoint];allowed_ip` spec string.
    pub fn to_spec(&self) -> String {
        format!(
            "{};{};{}",
            self.public_key,
            self.endpoint.as_deref().unwrap_or(""),
            self.allowed_ip
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_spec_with_endpoint() {
        let d = PeerDescriptor {
            public_key: "ab".repeat(32),
            allowed_ip: "10.0.99.2".to_string(),
            endpoint: Some("192.168.1.5:50002".to_string()),
        };
        assert_eq!(
            d.to_spec(),
            format!("{};192.168.1.5:50002;10.0.99.2", "ab".repeat(32))
        );
    }

    #[test]
    fn to_spec_inbound_only_has_empty_endpoint_field() {
        let d = PeerDescriptor {
            public_key: "cd".repeat(32),
            allowed_ip: "10.0.99.3".to_string(),
            endpoint: None,
        };
        assert_eq!(d.to_spec(), format!("{};;10.0.99.3", "cd".repeat(32)));
    }
}
