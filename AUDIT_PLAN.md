# AraxMesh Security Audit Plan

As a security-sensitive product implementing a custom overlay transport layer, **AraxMesh** must undergo systematic security audits before any deployment in production environments. This plan details the required security verification areas, automated validation tools, fuzzing strategies, and professional review scope.

---

## 1. Audit Target Areas

### 1.1 Cryptographic Protocol & State Machine
* **Noise Handshake**: Verify correct implementation of the `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake state machine, ensuring that public keys are verified, ephemeral keys are deleted immediately after use, and handshake states are properly cleared.
* **Symmetric Session State**: Review how the `ActiveSession` stores and rotates symmmetric keys.
  - Assert that old keys are zeroed out (e.g. using the `zeroize` crate) when replaced.
  - Verify that the 15-second grace period for the previous session's keys doesn't leak plaintext or session context.
* **Nonce Reuse Prevention**: Check that the monotonically incrementing `u64` nonces can never wrap or repeat under the same symmetric key.

### 1.2 Memory & Resource Management
* **DoS Resilience**: Assess how the UDP and TCP relay interfaces handle malformed packets, high-frequency handshake requests (handshake flooding), and extremely large payloads.
* **Buffer Safety**: Verify that all read buffers from TUN, UDP sockets, and TCP relay streams have strict length limits and do not cause memory inflation or panic vectors under heavy load.
* **Async Task Lifecycles**: Review the lifecycle of the five main Tokio tasks (`tun_to_udp`, `udp_to_tun`, `timer`, `coordinator_poll`, `relay`) to ensure that socket closures or panics in one task are handled gracefully without leaking other tasks or leaving zombie connections.

### 1.3 Cryptokey Routing & Isolation
* **LPM Correctness**: Review the longest-prefix-match (LPM) matching function (`find_best_peer_idx`) to ensure no incorrect matching or fallback behavior can leak packets destined for one peer to another peer.
* **Spoofing Prevention**: Verify that inbound packets successfully validated by trial decryption are rejected if their inner source IP does not match the allowed subnets of the decrypting peer.

---

## 2. Automated Validation and Static Analysis

Before a manual code audit, automated tools must verify code hygiene:

* **Dependency Auditing**:
  ```bash
  cargo install cargo-deny
  cargo deny check
  ```
  Ensure all dependencies are checked for known security vulnerabilities (Advisories), commercial licenses, and duplicate crates.
* **Lints and Safety**:
  ```bash
  cargo clippy --all-targets -- -D warnings
  ```
  Ensure `#![forbid(unsafe_code)]` remains enabled at the root of the library crate (`src/lib.rs`) and all binary binaries.

---

## 3. Fuzz Testing Strategy

We recommend using `cargo-fuzz` (which uses LLVM's `libFuzzer`) to fuzz the packet parsing and framing logic:

1. **IPv4 Header Parser Fuzzing**: Fuzz `parse_ipv4_header()` with arbitrary byte buffers to ensure it never panics or yields invalid offsets.
2. **TCP Relay Packet Framing**: Fuzz the length-prefixed TCP reader in `src/relay.rs` to verify that corrupt frames (e.g. extremely large length prefixes) do not result in out-of-memory or assertion failures.
3. **Decryption Ingestion**: Fuzz `decrypt_packet()` with corrupted ciphertext payloads to verify the Snow AEAD state does not panic or enter an undefined state.

---

## 4. Professional Third-Party Audit Scope

An external cryptographer/security firm should be engaged to review:
1. **The Transport Protocol Framing**: Assert that our 1-byte packet header format does not leak session metadata or state information.
2. **Hole Punching & Roaming Logic**: Review the NAT hole-punching protocol to verify that an external attacker cannot inject probe packets (`0x04`) to hijack or redirect existing peer tunnels.
3. **Relay Server Isolation**: Review the coordinator (`coordinatord`) code to ensure that one client cannot eavesdrop on or intercept packets routed to another client through the integrated relay server.
