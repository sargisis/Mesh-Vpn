#![no_main]
//! Fuzz the CIDR subnet parser and `contains` mask arithmetic.
//!
//! `Ipv4Subnet::from_str` parses peer `allowed_ip` config and coordinator-supplied
//! descriptors; `contains` does shift-based mask arithmetic where a bad prefix
//! length could overflow. Neither may panic on arbitrary input.
use araxmesh::packet::Ipv4Subnet;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(subnet) = Ipv4Subnet::from_str(s) {
            // A parsed subnet must do mask arithmetic without panicking, including
            // at the prefix_len == 0 and == 32 boundaries (shift-overflow guards).
            let probe = Ipv4Addr::new(
                data.first().copied().unwrap_or(0),
                data.get(1).copied().unwrap_or(0),
                data.get(2).copied().unwrap_or(0),
                data.get(3).copied().unwrap_or(0),
            );
            let _ = subnet.contains(probe);
            let _ = subnet.contains(subnet.addr);
        }
    }
});
