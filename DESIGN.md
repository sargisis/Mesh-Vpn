# AraxMesh Technical Design & Protocol Specification

This document provides a comprehensive technical overview and protocol specification for **AraxMesh**, a self-hosted, sovereign, encrypted overlay-network (Mesh VPN) built in Rust.

---

## 1. System Architecture

AraxMesh is divided into two distinct components: the **Data Plane** (responsible for packet capture, encryption, and routing) and the **Control Plane** (responsible for node registration, IP assignment, and peer discovery).

```
   +--------------------------------------------------------------+
   |                        OPERATING SYSTEM                      |
   |                                                              |
   |   +-------------------+              +-------------------+   |
   |   |    Applications   |              |    Network Stack  |   |
   |   +---------+---------+              +---------^---------+   |
   |             | (Reads/Writes Socket)            |             |
   +-------------|----------------------------------|-------------+
                 |                                  |
   +-------------v----------------------------------+-------------+
   |   AraxMesh TUN Interface (arax0)               |             |
   |   - Captures packets matching overlay subnet   |             |
   +-------------+----------------------------------|-------------+
                 | Raw IP Packet                    | Plaintext IP Packet
   +-------------v----------------------------------+-------------+
   |   AraxMesh Daemon (araxmesh)                   |             |
   |                                                |             |
   |   +--------------------------------------------+---------+   |
   |   | Data Plane                                           |   |
   |   | - Cryptokey Routing (LPM CIDR Matching)              |   |
   |   | - Noise IK State Machine (IK_25519_ChaChaPoly_BLAKE2s)|  |
   |   | - Anti-Replay Window (1024-bit Sliding Window)       |   |
   |   | - Obfuscation & Padding (DPI Bypass Engine)          |   |
   |   +---------------------+--------------------------------+   |
   |                         |                                    |
   |            Encrypted    | Encrypted Payload                  |
   |            UDP Packet   | (over TCP)                         |
   |                         |                                    |
   |             +-----------v-----------+                        |
   |             | Relay Fallback Client |                        |
   |             +-----------+-----------+                        |
   |                         |                                    |
   +-------------------------|------------------------------------+
                             |
             +---------------+---------------+
             |                               |
             v (UDP Endpoint)                v (TCP Connection)
     +---------------+               +---------------+
     |   Remote Peer |               |  Relay Server |
     +---------------+               +---------------+
```

### 1.1 Concurrency Model (Tokio Tasks)
The AraxMesh daemon manages five asynchronous, long-running loops sharing state via `Arc<Mutex<PeerManager>>`:

1. **`tun_to_udp`**:
   - Reads outbound plaintext IP packets from the TUN interface.
   - Extracts the destination IP address from the packet header.
   - Performs a **Longest Prefix Match (LPM)** lookup against allowed subnets.
   - Encrypts the packet and routes it to the matched peer via direct UDP or fallback TCP Relay.
2. **`udp_to_tun`**:
   - Listens on the bound UDP socket for incoming packets.
   - Decodes packet headers, routes handshakes to the Noise state machine, and decrypts transport data.
   - Validates the inner source IP against the decrypting peer's allowed subnets (Cryptokey routing).
   - Writes decrypted plaintext packets to the TUN interface.
3. **`timer`**:
   - Ticks every 1 second.
   - Monitors session lifetimes for key rotation, triggers keepalive packets, and purges stale sessions.
4. **`coordinator_poll`**:
   - Ticks every 10 seconds.
   - Sends poll requests to the coordinator to fetch peer tables and registry status.
5. **`relay`**:
   - Manages a persistent TCP socket to the relay server.
   - Routes outbound packets when direct UDP is blocked and processes incoming relayed frames.

---

## 2. Wire Protocol Specification

AraxMesh encapsulates raw IP payloads within a custom framing protocol before sending them over the wire. All integers are transmitted in network byte order (big-endian).

### 2.1 Packet Type Indicators (Custom Magic Signatures)
To prevent signature-based Deep Packet Inspection (DPI) blocks, the first byte of every wire packet represents a configurable type indicator. By default, the type bytes map to standard defaults, but they can be randomized in TOML configuration files:

| Packet Type | Default Header Byte | Description |
|---|---|---|
| **Handshake Initiation** | `0x01` | Initiates the Noise IK handshaking sequence. |
| **Handshake Response** | `0x02` | Completes the mutual key exchange. |
| **Transport Data** | `0x03` | Encapsulates encrypted IP network traffic. |
| **Hole-Punch Probe** | `0x04` | Single-byte packet used to establish NAT state tables. |

---

### 2.2 Handshake Packets (Noise IK Pattern)
Handshakes employ the `Noise_IK_25519_ChaChaPoly_BLAKE2s` protocol pattern.

#### Handshake Initiation
Sent by the initiator to establish a symmetric session.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Init Magic   |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                    Noise IK Ephemeral Key                     +
|                          (32 bytes)                           |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Encrypted Static Identity                   +
|                          (48 bytes)                           |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               | Encrypted MAC |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +               +
|                          (16 bytes)                           |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                     Random Handshake Padding                  |
|                          (0 - 64 bytes)                       |
+                                                               +
|                                                               |
```

* **Noise Message Size**: Fixed at `96` bytes.
* **Handshake Padding**: Random length (0–64 bytes) appended to the message. The receiver slices the buffer to the first 96 payload bytes (skipping the magic header) to isolate the Noise payload.

#### Handshake Response
Sent by the responder to complete the handshake.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Resp Magic   |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                    Noise IK Ephemeral Key                     +
|                          (32 bytes)                           |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Encrypted Payload Tag                     |
|                          (16 bytes)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Random Handshake Padding                  |
|                          (0 - 64 bytes)                       |
|                                                               |
```

* **Noise Message Size**: Fixed at `48` bytes.
* **Handshake Padding**: Random length (0–64 bytes) appended to the message. The receiver slices the buffer to the first 48 payload bytes (skipping the magic header).

---

### 2.3 Transport Data Packets
Used for transmitting encrypted overlay network frames.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data Magic   |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                     Monotonic Sequence Nonce                  |
|                            (8 bytes)                          |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                        Encrypted Payload                      +
|                      (including IP Packet                     |
|                  + Random Encrypted Padding                   |
|                        + 16-byte AEAD MAC)                    |
|                                                               |
```

* **Sequence Nonce**: A monotonically increasing `u64` initialized to `0` upon session establishment. It ensures unique AEAD inputs and prevents replay attacks.
* **Encrypted Payload Padding**:
  - Valid IP packets are appended with a random sequence of `0–128` bytes *before* encryption.
  - This embeds high-entropy noise within the ciphertext block, neutralizing packet length footprint analysis.
* **Decryption & Truncation**:
  - After decryption, the receiver inspects the IPv4 header's `Total Length` field (bytes 2 and 3 of the plaintext block).
  - The plaintext is truncated to this length, discarding trailing padding bytes.

---

## 3. Cryptographic Session Management

### 3.1 Handshake Initiation & Rekeying
Handshake negotiations occur over two conditions:
1. **Demand-driven**: An outbound packet matches a peer's allowed subnet, but no active session is established.
2. **Time/Volume limits**: An active session exceeds **120 seconds** in duration or transmits more than **1 GB** of payload data.

To avoid packet loss during rekeying:
- The active session is moved to `previous`.
- A new session negotiation is initiated.
- The `previous` session is kept active for a **15-second grace period**, allowing out-of-order packets encrypted under the old keys to be successfully decrypted.

### 3.2 Anti-Replay Filtering (RFC 6479)
To block packet injection attacks, AraxMesh implements a sliding-window filter based on RFC 6479.

- Each active session holds a **1024-bit bitmap** representing the history of received packet nonces.
- When an authenticated packet is decrypted:
  - If its nonce is greater than the highest nonce seen (`last`), the window shifts right, clearing bit positions that are newly exposed.
  - If the nonce is smaller than `last` but falls within the 1024-bit window, the bitmap is checked. If the bit is set, the packet is rejected. Otherwise, the bit is set, and the packet is forwarded to the TUN interface.
  - Nonces older than 1024 packets behind `last` are rejected.

---

## 4. NAT Traversal & Roaming

### 4.1 Hole Punching Sequence
To bypass NAT routers:
1. When nodes register, the coordinator captures their external source IP/port (acting as a STUN server).
2. During peer discovery, the coordinator sends the external endpoints to both nodes.
3. Both nodes concurrently fire a burst of **3 probe packets** (`magic_probe` byte) separated by a 200 ms interval to the other's external endpoint.
4. The outbound traffic punches a mapping in the NAT firewalls, allowing direct UDP packets to flow.

### 4.2 Relay Fallback (TCP DERP-like)
If UDP hole punching fails, the daemon falls back to an integrated TCP relay server:
- An outbound packet is wrapped in a TCP frame: `[32-byte Destination Public Key] [4-byte Big-Endian Length] [Encrypted Frame Payload]`.
- The relay server parses the destination key, lookup the active TCP connection of the destination peer, and routes the frame.

---

## 5. Security & Threat Mitigation Matrix

| Threat Vector | Mitigation Strategy | Protocol Mechanic |
|---|---|---|
| **Snooping/Eavesdropping** | Cryptographic Secrecy | Ephemeral Noise DH exchange + ChaCha20-Poly1305 AEAD encryption. |
| **VPN Fingerprinting** | Header Obfuscation | Configurable packet types randomize signature signatures from ISP analysis. |
| **Packet Length Analysis** | Plaintext Padding | Adds `0-128` bytes of random data inside the encryption block, breaking length footprints. |
| **Replay Attacks** | Anti-Replay Sliding Window | RFC 6479 sliding bitmap drop of duplicated / out-of-bounds nonces. |
| **IP Spoofing** | Inbound Cryptokey Routing | Decrypted packet source IPs must fall within the peer's allowed subnets. |
| **NAT Endpoint Roaming** | Dynamic Peer Roaming | If decryption succeeds under peer key, their UDP endpoint updates dynamically. |
| **Reconnection DoS** | Exponential Backoff | Tries reconnecting to coordinate/relay starting at 1 s, doubling to 30 s limit. |
