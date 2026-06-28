# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

AraxMesh — a self-hosted, encrypted overlay-network (mesh VPN) daemon written in Rust. It is the "Track A" learning transport from `ROADMAP.md`: a WireGuard-like data plane built from scratch (UDP + Noise + framing + TUN). It is explicitly **not** production crypto without an independent audit.

`ROADMAP.md` (in Russian) is the authoritative design document and phase plan; read it before making architectural decisions. The README is **stale** — it still documents Phase 0 (static-key, `--peer-udp` flag). The code in `src/main.rs` has progressed to Phase 2 (Noise handshake, multi-peer routing). Trust the code over the README.

## Commands

```bash
cargo build                 # debug build -> ./target/debug/araxmesh
cargo build --release
cargo run -- --gen-keys     # generate a Noise static keypair (private/public hex), then exits

# End-to-end smoke test: spins up two daemons in isolated network namespaces
# (ns_a/ns_b via veth), runs ping across the tunnel, prints both daemon logs.
# Requires sudo and root-capable netns; tears everything down on exit.
./test_mesh.sh
```

There is no unit test suite yet — `test_mesh.sh` is the integration test. The daemon requires `sudo`/`CAP_NET_ADMIN` to create the TUN device. Set `RUST_LOG=debug` for verbose `tracing` output.

Note `edition = "2024"` in `Cargo.toml` — a recent stable Rust toolchain is required.

### Running a node

The daemon needs `--tun-ip`, `--private-key` (64 hex chars), and at least one `--peer`. Peer format is `pubkey_hex;[endpoint];allowed_ip` (endpoint may be empty for a peer that only ever connects inbound):

```bash
sudo ./target/debug/araxmesh \
  --tun-ip 10.0.99.1 \
  --private-key <64-hex-chars> \
  --local-udp 0.0.0.0:50001 \
  --peer "<peer_pubkey_hex>;192.168.1.5:50002;10.0.99.2"
```

## Architecture

The code is split into a small library (`src/lib.rs`) plus a thin binary (`src/main.rs`) that just calls `araxmesh::run()`. Library modules: `daemon` (peer/session state — `Peer`, `ActiveSession`, `PeerManager` — and the runtime loop, including `run()`), `config` (CLI `Args`, TOML `FileConfig`, `resolve_settings`, `parse_peer_arg`), `packet` (`parse_ipv4_header`), and `types` (`PeerDescriptor`, shared with the future coordinator). The daemon is a single Tokio process running three concurrent tasks coordinated through one `Arc<Mutex<PeerManager>>`. `tokio::select!` exits the process when any task finishes.

The three tasks:
1. **tun_to_udp** — reads IP packets from the TUN device, looks up the peer whose `allowed_ip` matches the packet's destination IP (cryptokey routing), encrypts, sends over UDP. If no session exists, it kicks off a handshake.
2. **udp_to_tun** — receives UDP datagrams, dispatches by the 1-byte packet type, and writes decrypted IP packets back to the TUN device.
3. **timer** (1-second tick) — drives all time-based state machine transitions: key rotation, dead-session detection, keepalives, and handshake initiation/retransmission.

### Wire format

Each UDP datagram starts with a 1-byte type:
- `0x01` — handshake initiation (Noise message)
- `0x02` — handshake response (Noise message)
- `0x03` — transport data: `0x03 || nonce(8 bytes, big-endian u64) || ciphertext`

Overhead is 9 bytes (1 type + 8 nonce), which is why the TUN MTU is set to `1411` (`1420 - 9`).

### Crypto / session model

- Noise pattern `Noise_IK_25519_ChaChaPoly_BLAKE2s` via the `snow` crate. After handshake, sessions use `StatelessTransportState` with an explicit caller-managed nonce (sent on the wire) — this is why nonces are transmitted rather than implied.
- **Authentication**: the responder verifies the initiator's static key against the configured peer table (`get_remote_static()` must match a known peer's `pubkey`); unknown keys are rejected.
- **Cryptokey routing**: on decrypt, the inner packet's source IP must equal the peer's `allowed_ip`, mirroring WireGuard. Mismatches are dropped.
- **Key rotation** (`Peer::check_rotation`): triggered after 120s OR 1 GB sent. The old session is kept as `previous` for a 15s overlap so in-flight packets still decrypt, then dropped.
- **Roaming**: data packets are first matched by source endpoint; on failure, trial-decryption against all peers updates the peer's endpoint when one succeeds.
- **Liveness**: keepalive (empty encrypted packet) every 10s of TX idle; a session with no RX for 15s is torn down.

### Peer state

`Peer` holds `active`/`previous` `ActiveSession`s, an in-progress `HandshakeState`, and the last handshake packet for retransmission. `PeerManager` owns the local private key and the `Vec<Peer>`. Note peers are stored in a `Vec` and looked up by linear scan (`allowed_ip`, `endpoint`, or `pubkey`) — fine for a handful of peers, revisit if scaling.

## Conventions

- Errors in the packet hot paths are logged via `tracing` and the packet is dropped (return `None`) rather than propagated — the daemon should never crash on a malformed datagram. Only startup/config errors bubble up through `main`'s `Result`.
- Pubkeys in logs are hex-encoded via `hex::encode`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
