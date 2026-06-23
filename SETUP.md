# AraxMesh Setup and User Guide

This guide provides step-by-step instructions on compiling, configuring, and running **AraxMesh** nodes and coordinators, including how to run them in the background as systemd services.

---

## 1. Prerequisites and Building

AraxMesh requires a modern Rust toolchain (minimum Rust 1.75 with 2024 edition support).

To compile the binaries:

```bash
git clone https://github.com/your-username/Mesh-Vpn.git
cd Mesh-Vpn
cargo build --release
```

This generates two main binaries in `./target/release/`:
* `araxmesh` — The mesh VPN client daemon.
* `coordinatord` — The central coordinator and TCP relay server.

---

## 2. Generating Keypairs

AraxMesh uses Noise IK static keypairs for mutual authentication. Each node must have its own private key and share its public key.

To generate a new keypair:

```bash
./target/release/araxmesh --gen-keys
```

**Output Example:**
```text
Private Key (hex): 70eff1a198247752421712aeeb2556a46da3a8b6956cc5e6facef11476ecad7a
Public Key (hex):  051f53afe89cd221cdaf4790685024fba5235e287c235c8b6c777cac9b500f30
```

---

## 3. Coordinator Self-Hosting

The coordinator performs control-plane discovery, IP allocation, STUN-like external endpoint mapping, and hosts the integrated fallback TCP relay server.

### Command Line Start
To run the coordinator on a public virtual private server (VPS):

```bash
./target/release/coordinatord \
  --listen 0.0.0.0:51820 \
  --cidr 10.0.99.0/24 \
  --auth-key "your-secure-shared-token" \
  --relay-port 51821
```

### Running as a systemd service
To ensure the coordinator runs in the background and restarts on boot:

1. Create a systemd unit file at `/etc/systemd/system/arax-coordinator.service`:

```ini
[Unit]
Description=AraxMesh Control Plane Coordinator
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/coordinatord \
  --listen 0.0.0.0:51820 \
  --cidr 10.0.99.0/24 \
  --auth-key "your-secure-shared-token" \
  --relay-port 51821
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

2. Install the binary to `/usr/local/bin/coordinatord`:
```bash
sudo cp target/release/coordinatord /usr/local/bin/
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable arax-coordinator
sudo systemctl start arax-coordinator
```

---

## 4. Client Daemon Setup

AraxMesh client daemons run on each machine you wish to connect. Since they configure virtual `TUN` interfaces, they must run with root privileges (e.g. `sudo` or `CAP_NET_ADMIN`).

We recommend using a TOML configuration file.

### Step 1: Create a configuration file
Create a file named `/etc/araxmesh/node.toml` (secured with `chmod 600`):

```toml
# Node private key generated with --gen-keys
private_key = "YOUR_HEX_PRIVATE_KEY"

# Optional parameters and defaults
tun_name    = "arax0"
local_udp   = "0.0.0.0:50001"

# ─── Option A: Coordinator Mode (Recommended) ───
coordinator_url = "http://YOUR_COORDINATOR_IP:51820"
auth_key        = "your-secure-shared-token"
public_endpoint = "YOUR_NODE_PUBLIC_IP:50001"
relay_addr      = "YOUR_COORDINATOR_IP:51821"
hostname        = "my-laptop"

# ─── Option B: Static Mode (No Coordinator) ───
# If you prefer not to use a coordinator, uncomment the fields below:
# tun_ip = "10.0.99.1"
#
# [[peer]]
# public_key = "PEER_PUBLIC_KEY"
# endpoint   = "PEER_UDP_ENDPOINT_IP:PORT"
# allowed_ip = "10.0.99.2"
```

### Step 2: Running as a systemd service
To run the daemon persistently in the background:

1. Create a systemd unit file at `/etc/systemd/system/araxmesh.service`:

```ini
[Unit]
Description=AraxMesh Client Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/araxmesh --config /etc/araxmesh/node.toml
Restart=always
RestartSec=5
# Allow TUN creation capabilities if running as a non-root user (optional)
# CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

2. Copy the binary and config:
```bash
sudo mkdir -p /etc/araxmesh
sudo cp target/release/araxmesh /usr/local/bin/
sudo cp node.example.toml /etc/araxmesh/node.toml  # and edit it
```

3. Enable and start the daemon:
```bash
sudo systemctl daemon-reload
sudo systemctl enable araxmesh
sudo systemctl start araxmesh
```

---

## 5. Advanced Routing: Subnets & Exit Nodes

AraxMesh uses Longest Prefix Match (LPM) routing, allowing you to bridge local subnets or route all outbound traffic through an exit node.

### 5.1 Subnet Routing
If you want to expose a home network (e.g. `192.168.1.0/24`) through a server node:
1. Configure the server node's peer entry in other clients to include the subnet:
   ```toml
   allowed_ip = "10.0.99.2,192.168.1.0/24"
   ```
2. Enable IPv4 forwarding on the gateway node:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   # Persist in /etc/sysctl.conf
   ```
3. Set up NAT (masquerading) on the gateway node's physical interface (e.g. `eth0`):
   ```bash
   sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   sudo iptables -A FORWARD -i arax0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
   sudo iptables -A FORWARD -i eth0 -o arax0 -j ACCEPT
   ```

### 5.2 Exit Nodes (Default Route `0.0.0.0/0`)
To route all internet traffic through a remote peer (Exit Node):
1. Configure the remote peer's `allowed_ip` list on the local client to include the default route:
   ```toml
   allowed_ip = "10.0.99.2,0.0.0.0/0"
   ```
2. Configure IP forwarding and masquerading on the exit node server (as shown in section 5.1).

---

## 6. Verification and Troubleshooting

### Checking Interface State
To verify the interface has been created and has the correct IP:
```bash
ip addr show dev arax0
```

### Checking Logs
Both services output structured logs via `tracing`. To view logs:
```bash
# For coordinator
journalctl -u arax-coordinator -f

# For daemon
journalctl -u araxmesh -f
```

### Diagnostics
If nodes cannot reach each other:
1. Ensure the coordinator is reachable over HTTP at its `--listen` address.
2. If nodes are behind restrictive NATs and direct ping fails, check that the relay TCP connection is established (look for `"Connected to relay"` in client logs).
3. Verify that the Noise keys match exactly.
