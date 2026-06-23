//! CLI args, TOML device config, and resolution into effective settings.

use crate::types::PeerDescriptor;
use clap::Parser;
use std::net::SocketAddr;

pub(crate) struct ParsedPeer {
    pub(crate) pubkey: Vec<u8>,
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) allowed_ips: Vec<crate::packet::Ipv4Subnet>,
}

pub(crate) fn parse_peer_arg(s: &str) -> Result<ParsedPeer, Box<dyn std::error::Error>> {
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

    let allowed_ips: Result<Vec<crate::packet::Ipv4Subnet>, _> = allowed_ip_str
        .split(',')
        .map(|part| part.trim().parse::<crate::packet::Ipv4Subnet>())
        .collect();
    let allowed_ips = allowed_ips.map_err(|e| {
        format!("Invalid allowed IP(s) '{}': {}", allowed_ip_str, e)
    })?;

    Ok(ParsedPeer {
        pubkey,
        endpoint,
        allowed_ips,
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

    /// Path to a TOML config file. When given, it supplies the private key,
    /// TUN settings and peer table instead of the individual CLI flags.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// URL of the control-plane coordinator (HTTP).
    #[arg(long)]
    coordinator_url: Option<String>,

    /// Pre-auth key to register/poll the coordinator.
    #[arg(long)]
    auth_key: Option<String>,

    /// Hostname to register with the coordinator.
    #[arg(long)]
    hostname: Option<String>,

    /// Public UDP endpoint to advertise to the coordinator (e.g. 192.168.100.1:50000).
    #[arg(long)]
    public_endpoint: Option<String>,

    /// TCP relay server address (e.g. 192.168.100.1:51821).
    #[arg(long)]
    relay_addr: Option<String>,
}

/// Device configuration loaded from a TOML file (Phase 3 device config file).
/// Mirrors the CLI flags so a node can be described entirely by one file:
/// its own private key, TUN settings, and the peer table.
#[derive(serde::Deserialize, Debug)]
struct FileConfig {
    private_key: String,
    tun_ip: Option<String>,
    #[serde(default = "default_tun_name")]
    tun_name: String,
    #[serde(default = "default_tun_netmask")]
    tun_netmask: String,
    #[serde(default = "default_local_udp")]
    local_udp: String,
    #[serde(default)]
    peer: Vec<PeerDescriptor>,
    coordinator_url: Option<String>,
    relay_addr: Option<String>,
    auth_key: Option<String>,
    hostname: Option<String>,
    public_endpoint: Option<String>,
}

fn default_tun_name() -> String {
    "arax0".to_string()
}
fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}
fn default_local_udp() -> String {
    "0.0.0.0:50001".to_string()
}

/// Effective daemon settings after merging the config file or CLI flags into
/// one shape. Peers are kept as CLI-style specs and parsed downstream.
pub(crate) struct DaemonSettings {
    pub(crate) tun_name: String,
    pub(crate) tun_ip: Option<String>,
    pub(crate) tun_netmask: String,
    pub(crate) local_udp: SocketAddr,
    pub(crate) private_key_hex: String,
    pub(crate) peer_specs: Vec<String>,
    pub(crate) coordinator_url: Option<String>,
    pub(crate) relay_addr: Option<String>,
    pub(crate) auth_key: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) public_endpoint: Option<String>,
}

/// Resolve settings from `--config <file>` if given, otherwise from the CLI
/// flags (preserving the existing flag-driven behaviour relied on by tests).
fn resolve_settings(args: &Args) -> Result<DaemonSettings, Box<dyn std::error::Error>> {
    if let Some(path) = &args.config {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
        let cfg: FileConfig = toml::from_str(&text)
            .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;
        let local_udp = cfg
            .local_udp
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid local_udp '{}' in config: {}", cfg.local_udp, e))?;

        let relay_addr = cfg.relay_addr.or_else(|| {
            cfg.coordinator_url.as_ref().and_then(|url_str| {
                if let Ok(url) = reqwest::Url::parse(url_str) {
                    if let Some(host) = url.host_str() {
                        return Some(format!("{}:51821", host));
                    }
                }
                None
            })
        });

        Ok(DaemonSettings {
            tun_name: cfg.tun_name,
            tun_ip: cfg.tun_ip,
            tun_netmask: cfg.tun_netmask,
            local_udp,
            private_key_hex: cfg.private_key,
            peer_specs: cfg.peer.iter().map(PeerDescriptor::to_spec).collect(),
            coordinator_url: cfg.coordinator_url,
            relay_addr,
            auth_key: cfg.auth_key,
            hostname: cfg.hostname,
            public_endpoint: cfg.public_endpoint,
        })
    } else {
        let coordinator_url = args.coordinator_url.clone();
        let tun_ip = if coordinator_url.is_none() {
            Some(args.tun_ip.clone().ok_or_else(|| {
                "Missing required argument: --tun-ip (or use --config or --coordinator-url)".to_string()
            })?)
        } else {
            args.tun_ip.clone()
        };
        let private_key_hex = args.private_key.clone().ok_or_else(|| {
            "Missing required argument: --private-key (or use --config)".to_string()
        })?;

        let relay_addr = args.relay_addr.clone().or_else(|| {
            args.coordinator_url.as_ref().and_then(|url_str| {
                if let Ok(url) = reqwest::Url::parse(url_str) {
                    if let Some(host) = url.host_str() {
                        return Some(format!("{}:51821", host));
                    }
                }
                None
            })
        });

        Ok(DaemonSettings {
            tun_name: args.tun_name.clone(),
            tun_ip,
            tun_netmask: args.tun_netmask.clone(),
            local_udp: args.local_udp,
            private_key_hex,
            peer_specs: args.peer.clone(),
            coordinator_url: args.coordinator_url.clone(),
            relay_addr,
            auth_key: args.auth_key.clone(),
            hostname: args.hostname.clone(),
            public_endpoint: args.public_endpoint.clone(),
        })
    }
}

/// What the CLI asked us to do: print a fresh keypair, or run with settings.
pub(crate) enum Startup {
    GenKeys,
    Run(DaemonSettings),
}

/// Parse argv and resolve into a Startup decision (keeps Args private here).
pub(crate) fn parse_startup() -> Result<Startup, Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.gen_keys {
        Ok(Startup::GenKeys)
    } else {
        Ok(Startup::Run(resolve_settings(&args)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 64-hex-char (32-byte) public key, all bytes 0xab.
    fn valid_pubkey_hex() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn parse_peer_arg_full_form() {
        let s = format!("{};192.168.1.5:50002;10.0.99.2", valid_pubkey_hex());
        let p = parse_peer_arg(&s).expect("valid peer");
        assert_eq!(p.pubkey, vec![0xab; 32]);
        assert_eq!(p.endpoint, Some("192.168.1.5:50002".parse().unwrap()));
        assert_eq!(p.allowed_ips, vec!["10.0.99.2".parse::<crate::packet::Ipv4Subnet>().unwrap()]);
    }

    #[test]
    fn parse_peer_arg_empty_endpoint_is_inbound_only() {
        // Empty middle field => peer that only ever connects inbound.
        let s = format!("{};;10.0.99.2", valid_pubkey_hex());
        let p = parse_peer_arg(&s).expect("valid inbound-only peer");
        assert!(p.endpoint.is_none());
        assert_eq!(p.allowed_ips, vec!["10.0.99.2".parse::<crate::packet::Ipv4Subnet>().unwrap()]);
    }

    #[test]
    fn parse_peer_arg_rejects_wrong_field_count() {
        assert!(parse_peer_arg("only;two").is_err());
        let s = format!("{};192.168.1.5:50002;10.0.99.2;extra", valid_pubkey_hex());
        assert!(parse_peer_arg(&s).is_err());
    }

    #[test]
    fn parse_peer_arg_rejects_bad_pubkey_hex() {
        let s = format!("{};192.168.1.5:50002;10.0.99.2", "zz".repeat(32));
        assert!(parse_peer_arg(&s).is_err());
    }

    #[test]
    fn parse_peer_arg_rejects_wrong_pubkey_length() {
        // 30 bytes of valid hex, but the key must be exactly 32.
        let s = format!("{};192.168.1.5:50002;10.0.99.2", "ab".repeat(30));
        assert!(parse_peer_arg(&s).is_err());
    }

    #[test]
    fn parse_peer_arg_rejects_bad_endpoint() {
        let s = format!("{};not-an-endpoint;10.0.99.2", valid_pubkey_hex());
        assert!(parse_peer_arg(&s).is_err());
    }

    #[test]
    fn parse_peer_arg_rejects_bad_allowed_ip() {
        let s = format!("{};192.168.1.5:50002;not-an-ip", valid_pubkey_hex());
        assert!(parse_peer_arg(&s).is_err());
    }

    #[test]
    fn file_config_parses_full_toml() {
        let pk = valid_pubkey_hex();
        let toml = format!(
            r#"
            private_key = "{pk}"
            tun_ip = "10.0.99.1"
            tun_name = "arax9"
            local_udp = "0.0.0.0:50001"

            [[peer]]
            public_key = "{pk}"
            endpoint = "192.168.1.5:50002"
            allowed_ip = "10.0.99.2"

            [[peer]]
            public_key = "{pk}"
            allowed_ip = "10.0.99.3"
            "#
        );
        let cfg: FileConfig = toml::from_str(&toml).expect("valid config");
        assert_eq!(cfg.tun_name, "arax9");
        assert_eq!(cfg.tun_netmask, "255.255.255.0"); // default applied
        assert_eq!(cfg.peer.len(), 2);
        // Specs feed the same validator as the CLI; both must parse cleanly.
        for p in &cfg.peer {
            parse_peer_arg(&p.to_spec()).expect("config peer spec parses");
        }
        // Inbound-only peer (no endpoint) renders with an empty middle field.
        assert_eq!(cfg.peer[1].to_spec(), format!("{pk};;10.0.99.3"));
    }

    #[test]
    fn file_config_applies_defaults() {
        let toml = format!(
            "private_key = \"{}\"\ntun_ip = \"10.0.99.1\"\n",
            valid_pubkey_hex()
        );
        let cfg: FileConfig = toml::from_str(&toml).expect("minimal config");
        assert_eq!(cfg.tun_name, "arax0");
        assert_eq!(cfg.tun_netmask, "255.255.255.0");
        assert_eq!(cfg.local_udp, "0.0.0.0:50001");
        assert!(cfg.peer.is_empty());
    }

    #[test]
    fn file_config_rejects_missing_required_field() {
        // No private_key -> deserialization must fail.
        let toml = "tun_ip = \"10.0.99.1\"\n";
        assert!(toml::from_str::<FileConfig>(toml).is_err());
    }
}
