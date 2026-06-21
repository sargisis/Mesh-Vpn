# AraxMesh

**AraxMesh** is a self-hosted, sovereign, encrypted overlay-network (Mesh-VPN) written in Rust. It establishes end-to-end encrypted tunnels between devices (laptops, phones, servers) so that they behave as if they are on a single local area network (LAN), regardless of their physical location or network constraints.

---

## Architecture Overview

```
   Applications / OS
        │
   ┌────▼─────┐   Virtual Network Adapter (TUN)
   │   TUN    │   OS routes overlay traffic here
   └────┬─────┘
        │  IP Packets
   ┌────▼──────────────┐
   │   AraxMesh Daemon │
   │  ┌──────────────┐  │
   │  │ Framing /     │  │  ← Packet header formatting
   │  │ Transport    │  │
   │  ├──────────────┤  │
   │  │ Encryption   │  │  ← ChaCha20-Poly1305 (Phase 0 static key)
   │  └──────────────┘  │
   └────┬──────────────┘
        │  Encrypted Datagrams
   ┌────▼─────┐
   │   UDP    │
   └────┬─────┘
        │
   Public Internet ────► Remote Peer (Decrypted and sent to remote TUN)
```

---

## Current Status: Phase 0 (Skeleton)

Phase 0 implements the minimum viable data plane:
- Creates a virtual TUN interface on Linux.
- Captures outgoing IP packets from TUN, encrypts them using **ChaCha20-Poly1305** with a static key, and encapsulates them into UDP packets.
- Receives UDP packets from the peer, decrypts them, and writes the plain IP packets back to the local TUN interface.

---

## How to Build and Run (Phase 0)

### 1. Build the Binary
```bash
cargo build
```

### 2. Run Node A
Launch the daemon with a virtual IP of `10.0.99.1`, listening on UDP port `50001` and targeting Node B on port `50002`:
```bash
sudo ./target/debug/araxmesh \
  --tun-name arax0 \
  --tun-ip 10.0.99.1 \
  --local-udp 127.0.0.1:50001 \
  --peer-udp 127.0.0.1:50002
```

### 3. Run Node B
In another terminal, launch Node B with a virtual IP of `10.0.99.2`, listening on UDP port `50002` and targeting Node A on port `50001`:
```bash
sudo ./target/debug/araxmesh \
  --tun-name arax1 \
  --tun-ip 10.0.99.2 \
  --local-udp 127.0.0.1:50002 \
  --peer-udp 127.0.0.1:50001
```

### 4. Verify connectivity
From Node A's host (or Node B), ping the remote virtual IP through the created interface:
```bash
ping -I arax0 10.0.99.2
```
You should see successful ICMP ping responses.