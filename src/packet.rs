//! IP packet inspection and subnet routing structures.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// Inspects an IPv4 packet header to extract source and destination IP addresses.
pub(crate) fn parse_ipv4_header(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

/// Extracts the Total Length field from an IPv4 packet header.
pub(crate) fn parse_ipv4_total_length(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    Some(total_len)
}

/// Represents an IPv4 CIDR subnet (e.g. `192.168.1.0/24` or `10.0.99.2/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Subnet {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Subnet {
    /// Checks if a given IP address falls within the subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = !0u32 << (32 - self.prefix_len);
        let subnet_u32 = u32::from(self.addr) & mask;
        let ip_u32 = u32::from(ip) & mask;
        subnet_u32 == ip_u32
    }
}

impl FromStr for Ipv4Subnet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.is_empty() || parts.len() > 2 {
            return Err("Invalid CIDR format: expected A.B.C.D[/prefix]".to_string());
        }
        let addr = parts[0]
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid IPv4 address: {}", e))?;
        let prefix_len = if parts.len() == 2 {
            let len = parts[1]
                .parse::<u8>()
                .map_err(|e| format!("invalid prefix length: {}", e))?;
            if len > 32 {
                return Err("Prefix length must be between 0 and 32".to_string());
            }
            len
        } else {
            32
        };
        Ok(Ipv4Subnet { addr, prefix_len })
    }
}

impl std::fmt::Display for Ipv4Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Minimal 20-byte IPv4 header with the given version/IHL byte and addrs.
    fn make_ipv4(version_ihl: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = version_ihl;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn parse_ipv4_header_extracts_src_and_dst() {
        let pkt = make_ipv4(0x45, [10, 0, 99, 1], [10, 0, 99, 2]);
        let (src, dst) = parse_ipv4_header(&pkt).expect("valid IPv4 header");
        assert_eq!(src, Ipv4Addr::new(10, 0, 99, 1));
        assert_eq!(dst, Ipv4Addr::new(10, 0, 99, 2));
    }

    #[test]
    fn test_parse_ipv4_total_length() {
        let mut pkt = make_ipv4(0x45, [10, 0, 99, 1], [10, 0, 99, 2]);
        pkt[2] = 0x00;
        pkt[3] = 0x28;
        assert_eq!(parse_ipv4_total_length(&pkt).unwrap(), 40);

        pkt[0] = 0x55;
        assert!(parse_ipv4_total_length(&pkt).is_none());

        assert!(parse_ipv4_total_length(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_ipv4_header_rejects_short_packet() {
        assert!(parse_ipv4_header(&[0u8; 19]).is_none());
        assert!(parse_ipv4_header(&[]).is_none());
    }

    #[test]
    fn parse_ipv4_header_rejects_non_ipv4_version() {
        let pkt = make_ipv4(0x60, [10, 0, 99, 1], [10, 0, 99, 2]);
        assert!(parse_ipv4_header(&pkt).is_none());
    }

    #[test]
    fn ipv4_subnet_contains() {
        // Host route /32
        let sub_host: Ipv4Subnet = "10.0.99.2/32".parse().unwrap();
        assert!(sub_host.contains(Ipv4Addr::new(10, 0, 99, 2)));
        assert!(!sub_host.contains(Ipv4Addr::new(10, 0, 99, 3)));

        // Subnet route /24
        let sub_net: Ipv4Subnet = "192.168.1.0/24".parse().unwrap();
        assert!(sub_net.contains(Ipv4Addr::new(192, 168, 1, 5)));
        assert!(sub_net.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!sub_net.contains(Ipv4Addr::new(192, 168, 2, 1)));

        // Default route /0
        let sub_default: Ipv4Subnet = "0.0.0.0/0".parse().unwrap();
        assert!(sub_default.contains(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(sub_default.contains(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn ipv4_subnet_defaults_to_32() {
        let sub: Ipv4Subnet = "10.0.0.1".parse().unwrap();
        assert_eq!(sub.prefix_len, 32);
        assert_eq!(sub.addr, Ipv4Addr::new(10, 0, 0, 1));
    }
}
