#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Cleanup function to run on exit
cleanup() {
    echo "=== Cleaning up network namespaces ==="
    sudo ip netns delete ns_a 2>/dev/null || true
    sudo ip netns delete ns_b 2>/dev/null || true
    rm -f daemon_a.log daemon_b.log
    echo "Cleanup complete."
}

# Run cleanup on script exit (Ctrl+C, normal exit, etc.)
trap cleanup EXIT

echo "=== Creating network namespaces: ns_a and ns_b ==="
sudo ip netns add ns_a
sudo ip netns add ns_b

echo "=== Creating veth pair ==="
sudo ip link add veth_a type veth peer name veth_b

echo "=== Moving veth interfaces to namespaces ==="
sudo ip link set veth_a netns ns_a
sudo ip link set veth_b netns ns_b

echo "=== Configuring veth interfaces ==="
sudo ip netns exec ns_a ip addr add 192.168.100.1/24 dev veth_a
sudo ip netns exec ns_a ip link set veth_a up
sudo ip netns exec ns_a ip link set lo up

sudo ip netns exec ns_b ip addr add 192.168.100.2/24 dev veth_b
sudo ip netns exec ns_b ip link set veth_b up
sudo ip netns exec ns_b ip link set lo up

echo "=== Building AraxMesh ==="
cargo build

echo "=== Starting AraxMesh Daemon A in ns_a ==="
sudo RUST_LOG=debug ip netns exec ns_a ./target/debug/araxmesh \
  --tun-name arax0 \
  --tun-ip 10.0.99.1 \
  --local-udp 192.168.100.1:50000 \
  --peer-udp 192.168.100.2:50000 > daemon_a.log 2>&1 &
PID_A=$!

echo "=== Starting AraxMesh Daemon B in ns_b ==="
sudo RUST_LOG=debug ip netns exec ns_b ./target/debug/araxmesh \
  --tun-name arax1 \
  --tun-ip 10.0.99.2 \
  --local-udp 192.168.100.2:50000 \
  --peer-udp 192.168.100.1:50000 > daemon_b.log 2>&1 &
PID_B=$!

# Give daemons a moment to initialize and bring up TUN interfaces
sleep 2

echo "=== Running ping from ns_a (10.0.99.1) to ns_b (10.0.99.2) ==="
sudo ip netns exec ns_a ping -c 4 10.0.99.2

echo "=== Logs for Daemon A ==="
cat daemon_a.log

echo "=== Logs for Daemon B ==="
cat daemon_b.log

# Terminate daemons
sudo kill $PID_A $PID_B 2>/dev/null || true
wait $PID_A $PID_B 2>/dev/null || true
