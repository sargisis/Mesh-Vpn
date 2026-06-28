#!/usr/bin/env bash
#
# AraxMesh coordination integration test — Phase 3.
#
# Spins up coordinatord inside ns_a. Then starts three daemons in isolated
# namespaces ns_a, ns_b, ns_c. They register with coordinatord, automatically
# obtain their assigned overlay IPs and peer tables, and dynamically poll
# to synchronize peer endpoints.
# Then runs the full ping matrix and fails if any pair cannot reach each other.
#
# Requires sudo and root-capable netns. Tears everything down on exit.

set -euo pipefail

BRIDGE="araxbr0"
NODES=(a b c)
declare -A UNDERLAY=( [a]=192.168.100.1 [b]=192.168.100.2 [c]=192.168.100.3 )
declare -A OVERLAY=(  [a]=10.0.99.1      [b]=10.0.99.2      [c]=10.0.99.3 )
UDP_PORT=50000

declare -A PRIV PUB PID
COORDINATORD_PID=""

cleanup() {
    echo "=== Cleaning up ==="
    for n in "${NODES[@]}"; do
        [[ -n "${PID[$n]:-}" ]] && sudo kill "${PID[$n]}" 2>/dev/null || true
        sudo ip netns delete "ns_$n" 2>/dev/null || true
        sudo ip link delete "vh_$n" 2>/dev/null || true
    done
    [[ -n "$COORDINATORD_PID" ]] && sudo kill "$COORDINATORD_PID" 2>/dev/null || true
    sudo ip link delete "$BRIDGE" 2>/dev/null || true
    rm -f daemon_*.log coordinatord.log
    echo "Cleanup complete."
}
trap cleanup EXIT

echo "=== Building AraxMesh and Coordinator ==="
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    sudo -u "$SUDO_USER" env HOME="$USER_HOME" \
        PATH="$USER_HOME/.cargo/bin:$PATH" cargo build --bins
else
    cargo build --bins
fi

echo "=== Generating Noise keypairs ==="
for n in "${NODES[@]}"; do
    OUT=$(./target/debug/araxmesh --gen-keys)
    PRIV[$n]=$(echo "$OUT" | awk '/Private Key/ {print $NF}')
    PUB[$n]=$(echo "$OUT"  | awk '/Public Key/  {print $NF}')
    echo "  ns_$n pub=${PUB[$n]}"
done

echo "=== Creating bridge $BRIDGE ==="
sudo ip link add "$BRIDGE" type bridge
sudo ip link set "$BRIDGE" up

echo "=== Creating namespaces and wiring them to the bridge ==="
for n in "${NODES[@]}"; do
    sudo ip netns add "ns_$n"
    sudo ip link add "vh_$n" type veth peer name veth0 netns "ns_$n"
    sudo ip link set "vh_$n" master "$BRIDGE"
    sudo ip link set "vh_$n" up
    sudo ip netns exec "ns_$n" ip addr add "${UNDERLAY[$n]}/24" dev veth0
    sudo ip netns exec "ns_$n" ip link set veth0 up
    sudo ip netns exec "ns_$n" ip link set lo up
done

echo "=== Starting Coordinatord inside ns_a ==="
# Coordinatord binds to 0.0.0.0:51820 inside ns_a.
# Since namespaces are on the same bridge network (192.168.100.0/24),
# others can reach it at http://192.168.100.1:51820.
sudo ip netns exec ns_a ./target/debug/coordinatord \
    --listen "0.0.0.0:51820" \
    --cidr "10.0.99.0/24" \
    --auth-key "test-secret-key" > coordinatord.log 2>&1 &
COORDINATORD_PID=$!
echo "  coordinatord started (pid $COORDINATORD_PID)"

# Wait for coordinatord to start listening
sleep 1

echo "=== Starting client daemons ==="
for n in "${NODES[@]}"; do
    sudo RUST_LOG=debug ip netns exec "ns_$n" ./target/debug/araxmesh \
        --tun-name arax0 \
        --local-udp "${UNDERLAY[$n]}:${UDP_PORT}" \
        --private-key "${PRIV[$n]}" \
        --coordinator-url "http://192.168.100.1:51820" \
        --auth-key "test-secret-key" \
        --hostname "node-$n" \
        --public-endpoint "${UNDERLAY[$n]}:${UDP_PORT}" > "daemon_$n.log" 2>&1 &
    PID[$n]=$!
    echo "  ns_$n daemon started (pid ${PID[$n]})"
    sleep 1
done

# Give daemons time to register, fetch peer tables, and build TUN interfaces.
sleep 12

echo "=== Ping matrix (every node -> every other node) ==="
FAILURES=0
for s in "${NODES[@]}"; do
    for d in "${NODES[@]}"; do
        [[ "$s" == "$d" ]] && continue
        target="${OVERLAY[$d]}"
        # -c 3 gives the Noise handshake a couple of round trips to settle.
        if sudo ip netns exec "ns_$s" ping -c 3 -W 3 "$target" > /dev/null 2>&1; then
            echo "  ok   ns_$s -> $target"
        else
            echo "  FAIL ns_$s -> $target"
            FAILURES=$((FAILURES + 1))
        fi
    done
done

echo
if [[ "$FAILURES" -eq 0 ]]; then
    echo "=== PASS: all $(( ${#NODES[@]} * (${#NODES[@]} - 1) )) directed pairs reachable ==="
else
    echo "=== FAIL: $FAILURES pair(s) unreachable — logs below ==="
    echo "----- coordinatord.log -----"
    cat coordinatord.log
    for n in "${NODES[@]}"; do
        echo "----- daemon_$n.log -----"
        cat "daemon_$n.log"
    done
    exit 1
fi
