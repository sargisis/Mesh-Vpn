#![no_main]
//! Fuzz the IPv4 header parser on the packet hot path.
//!
//! `parse_ipv4_header` runs on every datagram decrypted from a peer, so it sees
//! attacker-controlled bytes. It must return `None` on anything malformed and
//! must NEVER panic (no out-of-bounds slicing, no arithmetic overflow).
use araxmesh::packet::parse_ipv4_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The only contract under fuzzing: never panic on arbitrary input.
    let _ = parse_ipv4_header(data);
});
