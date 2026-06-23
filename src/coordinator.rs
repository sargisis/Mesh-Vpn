//! Coordinator state: the network registry and overlay-IP allocator.
//!
//! This is the control-plane "source of truth": which nodes are in the network,
//! their assigned overlay IPs and last-known endpoints. The HTTP server in
//! `bin/coordinatord.rs` is a thin shell around this; keeping the logic here
//! lets it be unit-tested without a socket.

use crate::types::PeerDescriptor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Allocates host addresses out of an IPv4 CIDR (e.g. `10.0.99.0/24`).
#[derive(Debug, Clone)]
pub struct IpAllocator {
    network: u32,
    prefix: u8,
}

impl IpAllocator {
    /// Parse a `A.B.C.D/prefix` block.
    pub fn new(cidr: &str) -> Result<Self, String> {
        let (addr, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| format!("CIDR '{cidr}' must be in A.B.C.D/prefix form"))?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("invalid network address in '{cidr}': {e}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|e| format!("invalid prefix in '{cidr}': {e}"))?;
        if prefix > 30 {
            return Err(format!("prefix /{prefix} leaves no usable host range"));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(addr) & mask;
        Ok(Self { network, prefix })
    }

    /// Inclusive range of usable host addresses (network+1 .. broadcast-1).
    fn host_range(&self) -> (u32, u32) {
        let size = 1u32 << (32 - self.prefix);
        let broadcast = self.network | (size - 1);
        (self.network + 1, broadcast - 1)
    }

    /// Lowest host address not present in `used`, or `None` if the pool is full.
    pub fn next_free(&self, used: &dyn Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        let (first, last) = self.host_range();
        (first..=last).map(Ipv4Addr::from).find(|ip| !used(*ip))
    }
}

/// One registered node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    pub public_key: String,
    pub allowed_ip: String,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// The external `ip:port` as seen by the coordinator's TCP accept
    /// (STUN-like reflexive address). Stored so it can be returned on
    /// re-registration and compared with the self-reported endpoint.
    #[serde(default)]
    pub observed_endpoint: Option<String>,
}

/// The network registry: every node keyed by its public key, plus the
/// allocator and an optional JSON file to persist to.
pub struct Registry {
    allocator: IpAllocator,
    nodes: HashMap<String, NodeRecord>,
    path: Option<PathBuf>,
}

impl Registry {
    /// In-memory registry over `cidr` (no persistence). Used by tests.
    pub fn new(cidr: &str) -> Result<Self, String> {
        Ok(Self {
            allocator: IpAllocator::new(cidr)?,
            nodes: HashMap::new(),
            path: None,
        })
    }

    /// Registry backed by a JSON file: load existing nodes if the file exists,
    /// otherwise start empty. Subsequent mutations are flushed to `path`.
    pub fn load_or_new(cidr: &str, path: PathBuf) -> Result<Self, String> {
        let mut reg = Self::new(cidr)?;
        if path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("reading state file {}: {e}", path.display()))?;
            reg.nodes = serde_json::from_str(&text)
                .map_err(|e| format!("parsing state file {}: {e}", path.display()))?;
        }
        reg.path = Some(path);
        Ok(reg)
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(path) = &self.path {
            let text = serde_json::to_string_pretty(&self.nodes)
                .map_err(|e| format!("serializing registry: {e}"))?;
            std::fs::write(path, text)
                .map_err(|e| format!("writing state file {}: {e}", path.display()))?;
        }
        Ok(())
    }

    /// Register a node (or update an existing one). The overlay IP is allocated
    /// once and stays stable for that public key across re-registration.
    /// Returns `(assigned_ip, observed_endpoint)`.
    pub fn register(
        &mut self,
        public_key: &str,
        endpoint: String,
        hostname: Option<String>,
        observed_endpoint: Option<String>,
    ) -> Result<(String, Option<String>), String> {
        if let Some(existing) = self.nodes.get_mut(public_key) {
            existing.endpoint = Some(endpoint);
            if hostname.is_some() {
                existing.hostname = hostname;
            }
            existing.observed_endpoint = observed_endpoint.clone();
            let ip = existing.allowed_ip.clone();
            self.persist()?;
            return Ok((ip, observed_endpoint));
        }

        let used: std::collections::HashSet<Ipv4Addr> = self
            .nodes
            .values()
            .filter_map(|n| n.allowed_ip.parse().ok())
            .collect();
        let ip = self
            .allocator
            .next_free(&|ip| used.contains(&ip))
            .ok_or_else(|| "address pool exhausted".to_string())?;

        self.nodes.insert(
            public_key.to_string(),
            NodeRecord {
                public_key: public_key.to_string(),
                allowed_ip: ip.to_string(),
                endpoint: Some(endpoint),
                hostname,
                observed_endpoint: observed_endpoint.clone(),
            },
        );
        self.persist()?;
        Ok((ip.to_string(), observed_endpoint))
    }

    /// Refresh an already-registered node's endpoint. Errors if unknown.
    pub fn poll(
        &mut self,
        public_key: &str,
        endpoint: String,
        observed_endpoint: Option<String>,
    ) -> Result<(), String> {
        let node = self
            .nodes
            .get_mut(public_key)
            .ok_or_else(|| format!("unknown node {public_key}"))?;
        node.endpoint = Some(endpoint);
        node.observed_endpoint = observed_endpoint;
        self.persist()
    }

    /// The peer table from one node's perspective: every *other* node.
    pub fn peers_for(&self, public_key: &str) -> Vec<PeerDescriptor> {
        self.nodes
            .values()
            .filter(|n| n.public_key != public_key)
            .map(|n| PeerDescriptor {
                public_key: n.public_key.clone(),
                allowed_ip: n.allowed_ip.clone(),
                endpoint: n.endpoint.clone(),
            })
            .collect()
    }

    /// Whether a node is registered.
    pub fn is_registered(&self, public_key: &str) -> bool {
        self.nodes.contains_key(public_key)
    }

    /// A debug snapshot of the whole network.
    pub fn network_view(&self) -> NetworkView {
        let mut nodes: Vec<NodeRecord> = self.nodes.values().cloned().collect();
        nodes.sort_by(|a, b| a.allowed_ip.cmp(&b.allowed_ip));
        NetworkView { nodes }
    }
}

/// Serialisable snapshot of every registered node (served at `GET /network`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkView {
    pub nodes: Vec<NodeRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_hands_out_sequential_hosts() {
        let alloc = IpAllocator::new("10.0.99.0/24").unwrap();
        let used: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
        // First free host is .1 (network is .0).
        assert_eq!(
            alloc.next_free(&|ip| used.contains(&ip)),
            Some(Ipv4Addr::new(10, 0, 99, 1))
        );
    }

    #[test]
    fn allocator_skips_used_hosts() {
        let alloc = IpAllocator::new("10.0.99.0/24").unwrap();
        let mut used = std::collections::HashSet::new();
        used.insert(Ipv4Addr::new(10, 0, 99, 1));
        used.insert(Ipv4Addr::new(10, 0, 99, 2));
        assert_eq!(
            alloc.next_free(&|ip| used.contains(&ip)),
            Some(Ipv4Addr::new(10, 0, 99, 3))
        );
    }

    #[test]
    fn allocator_rejects_bad_cidr() {
        assert!(IpAllocator::new("not-a-cidr").is_err());
        assert!(IpAllocator::new("10.0.0.0/33").is_err());
        assert!(IpAllocator::new("10.0.0.0/31").is_err());
    }

    #[test]
    fn register_assigns_sequential_ips() {
        let mut reg = Registry::new("10.0.99.0/24").unwrap();
        let (a, _) = reg
            .register("aa", "1.1.1.1:50000".into(), Some("a".into()), None)
            .unwrap();
        let (b, _) = reg.register("bb", "2.2.2.2:50000".into(), None, None).unwrap();
        assert_eq!(a, "10.0.99.1");
        assert_eq!(b, "10.0.99.2");
    }

    #[test]
    fn register_is_stable_for_same_pubkey() {
        let mut reg = Registry::new("10.0.99.0/24").unwrap();
        let (first, _) = reg.register("aa", "1.1.1.1:1".into(), None, None).unwrap();
        // Re-register with a new endpoint: same IP, endpoint updated.
        let (again, _) = reg.register("aa", "9.9.9.9:9".into(), None, None).unwrap();
        assert_eq!(first, again);
        assert_eq!(reg.nodes.len(), 1);
        assert_eq!(reg.nodes["aa"].endpoint.as_deref(), Some("9.9.9.9:9"));
    }

    #[test]
    fn peers_for_excludes_self() {
        let mut reg = Registry::new("10.0.99.0/24").unwrap();
        reg.register("aa", "1.1.1.1:1".into(), None, None).unwrap();
        reg.register("bb", "2.2.2.2:2".into(), None, None).unwrap();
        reg.register("cc", "3.3.3.3:3".into(), None, None).unwrap();

        let peers = reg.peers_for("aa");
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|p| p.public_key != "aa"));
        let bb = peers.iter().find(|p| p.public_key == "bb").unwrap();
        assert_eq!(bb.allowed_ip, "10.0.99.2");
        assert_eq!(bb.endpoint.as_deref(), Some("2.2.2.2:2"));
    }

    #[test]
    fn poll_rejects_unknown_node() {
        let mut reg = Registry::new("10.0.99.0/24").unwrap();
        assert!(reg.poll("ghost", "1.2.3.4:5".into(), None).is_err());
    }

    #[test]
    fn load_or_new_round_trips_through_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("araxmesh_reg_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let mut reg = Registry::load_or_new("10.0.99.0/24", path.clone()).unwrap();
            reg.register("aa", "1.1.1.1:1".into(), Some("host-a".into()), None)
                .unwrap();
        }
        // Reload from disk: the node and its assignment survive.
        let reg = Registry::load_or_new("10.0.99.0/24", path.clone()).unwrap();
        assert!(reg.is_registered("aa"));
        assert_eq!(reg.nodes["aa"].allowed_ip, "10.0.99.1");

        let _ = std::fs::remove_file(&path);
    }
}
