//! IP packet inspection for cryptokey routing.

pub(crate) fn parse_ipv4_header(packet: &[u8]) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
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
    fn parse_ipv4_header_rejects_short_packet() {
        assert!(parse_ipv4_header(&[0u8; 19]).is_none());
        assert!(parse_ipv4_header(&[]).is_none());
    }

    #[test]
    fn parse_ipv4_header_rejects_non_ipv4_version() {
        // 0x60 => version 6: cryptokey routing only handles IPv4 here.
        let pkt = make_ipv4(0x60, [10, 0, 99, 1], [10, 0, 99, 2]);
        assert!(parse_ipv4_header(&pkt).is_none());
    }
}
