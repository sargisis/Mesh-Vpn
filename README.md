# AraxMesh

**AraxMesh** is a self-hosted, sovereign, encrypted overlay-network (Mesh VPN) written in Rust. It establishes end-to-end encrypted tunnels between devices (laptops, phones, servers) so that they behave as if they are on a single local area network, regardless of their physical location.

---

## Features

- **Noise IK handshake** (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) via the `snow` crate — mutual authentication with static keys.
- **Cryptokey routing** — packets are routed to the correct peer based on the destination IP inside the encrypted payload, mirroring WireGuard.
- **Automatic key rotation** — sessions are rekeyed after 120 seconds or 1 GB of transmitted data.
- **Peer roaming** — trial decryption detects when a peer's IP changes and updates the endpoint automatically.
- **Keepalive & dead-session detection** — empty encrypted packets every 10 s of TX idle; sessions torn down after 15 s of RX silence.
- **Self-hosted coordinator (control plane)** — an HTTP/JSON service where nodes register, obtain overlay IPs, and discover peers dynamically.
- **Dynamic peer synchronisation** — daemon polls the coordinator every 10 s and reconciles the peer table without restarting.
- **TOML config file** — a single file describes an entire node (private key, TUN settings, peer table or coordinator URL).
- **NAT Traversal (Phase 4)**:
  - **STUN-like discovery** — coordinator automatically detects real external IP/port via the TCP registration connection.
  - **UDP Hole Punching** — peers exchange hole-punching probes (`0x04` packets) to puncture local NAT state tables.
  - **TCP Relay Fallback (DERP-like)** — transparent fallback routing of encrypted Noise packets over a TCP relay server if direct UDP handshake fails.

---

## Architecture

```
   Applications / OS
        │
   ┌────▼─────┐   Virtual Network Adapter (TUN)
   │   TUN    │   OS routes overlay traffic here
   └────┬─────┘
        │  IP Packets
   ┌────▼──────────────┐
   │  AraxMesh Daemon  │
   │  ┌──────────────┐ │
   │  │ Framing /    │ │  ← 1-byte type + 8-byte nonce + ciphertext
   │  │ Transport    │ │
   │  ├──────────────┤ │
   │  │ Noise + AEAD │ │  ← Noise_IK + ChaCha20-Poly1305
   │  └──────────────┘ │
   └────┬──────────────┘
        │  Encrypted Datagrams
   ┌────▼─────┐
   │   UDP    │
   └────┬─────┘
        │
   Public Internet ────► Remote Peer (reverse path)
```

The daemon runs **five concurrent Tokio tasks** over a shared `Arc<Mutex<PeerManager>>`:

| Task | Role |
|---|---|
| `tun_to_udp` | Reads IP packets from TUN → encrypts → sends via UDP or Relay |
| `udp_to_tun` | Receives UDP → decrypts/handshakes → writes to TUN |
| `timer` | Key rotation, keepalive, dead-session cleanup (1 s tick) |
| `coordinator_poll` | Polls the coordinator for peer table updates (10 s tick) |
| `relay` | Maintains TCP connection to the relay server, routing relayed packets |

---

## Quick Start

### 1. Build

```bash
cargo build          # debug
cargo build --release
```

Requires a recent stable Rust toolchain (`edition = "2024"`).

### 2. Generate a keypair

```bash
./target/debug/araxmesh --gen-keys
# Private Key (hex): <64 hex chars>
# Public Key  (hex): <64 hex chars>
```

### 3a. Run with a coordinator (recommended)

**Start the coordinator** on one machine:

```bash
./target/debug/coordinatord \
  --listen 0.0.0.0:51820 \
  --cidr 10.0.99.0/24 \
  --auth-key "my-secret-token" \
  --relay-port 51821
```

**Start each node** (no manual peer configuration needed, automatically attempts UDP hole punching and falls back to relay if needed):

```bash
sudo ./target/debug/araxmesh \
  --private-key <64-hex-chars> \
  --coordinator-url http://<coordinator-ip>:51820 \
  --auth-key "my-secret-token" \
  --public-endpoint <this-node-public-ip>:50001 \
  --relay-addr <coordinator-ip>:51821
```

The node will register with the coordinator, receive an overlay IP, and automatically discover all other registered peers.

### 3b. Run with static peers (no coordinator)

```bash
sudo ./target/debug/araxmesh \
  --tun-ip 10.0.99.1 \
  --private-key <64-hex-chars> \
  --local-udp 0.0.0.0:50001 \
  --peer "<peer_pubkey_hex>;192.168.1.5:50002;10.0.99.2"
```

### 3c. Run with a TOML config file

```bash
sudo ./target/debug/araxmesh --config node.toml
```

See `node.example.toml` for the full format.

### 4. Verify

```bash
ping 10.0.99.2   # from any node in the mesh
```

---

## Integration Tests

```bash
# Phase 2 test: 3 nodes with static peer configs
sudo ./test_mesh.sh

# Phase 3 test: 3 nodes registering via coordinatord
sudo ./test_coordination.sh
```

Both scripts create isolated Linux network namespaces, run a full ping matrix, and clean up on exit.

---

## Project Structure

```
src/
├── main.rs          # Binary entry point — calls araxmesh::run()
├── lib.rs           # Library root — exports modules
├── daemon.rs        # Data plane: Peer, ActiveSession, PeerManager, run()
├── config.rs        # CLI args, TOML config, settings resolution
├── nat.rs           # NAT Traversal: hole punching and STUN discovery helpers
├── relay.rs         # Relay Fallback: length-prefixed TCP relay client
├── coordinator.rs   # Control plane: Registry, IpAllocator, NetworkView
├── control.rs       # Wire models: RegisterRequest/Response, PollRequest/Response
├── packet.rs        # parse_ipv4_header() for cryptokey routing
├── types.rs         # PeerDescriptor (shared between daemon and coordinator)
└── bin/
    └── coordinatord.rs  # Coordinator daemon with integrated TCP relay server
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full phased plan.

| Phase | Description | Status |
|---|---|---|
| 0 | Skeleton — TUN + static-key encryption | ✅ |
| 1 | Noise IK handshake via `snow` | ✅ |
| 2 | Multi-peer routing, keepalive, key rotation | ✅ |
| 3 | Self-hosted coordinator (control plane) | ✅ |
| 4 | NAT traversal (STUN + hole punch + relay) | ✅ |
| 5 | Exit-node mode, subnet routing, CLI UX | ⬜ |
| 6 | Release, docs, independent audit plan | ⬜ |

---

## License

MIT