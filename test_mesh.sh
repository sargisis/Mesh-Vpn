#!/usr/bin/env bash
#
# AraxMesh integration test — Phase 2 gate.
#
# Spins up THREE daemons in isolated network namespaces (ns_a/ns_b/ns_c),
# all sharing one underlay via a Linux bridge, each holding a real Noise
# static keypair and a peer table for the other two. Then runs the full
# ping matrix (every node pings every other node over the encrypted tunnel)
# and fails if any pair cannot reach the other.
#
# Requires sudo and root-capable netns. Tears everything down on exit.

set -euo pipefail

# --- Topology -----------------------------------------------------------
# Underlay (veth, on the bridge):   ns_a 192.168.100.1   ns_b .2   ns_c .3
# Overlay  (TUN, cryptokey-routed): ns_a 10.0.99.1       ns_b .2   ns_c .3
BRIDGE="araxbr0"
NODES=(a b c)
declare -A UNDERLAY=( [a]=192.168.100.1 [b]=192.168.100.2 [c]=192.168.100.3 )
declare -A OVERLAY=(  [a]=10.0.99.1      [b]=10.0.99.2      [c]=10.0.99.3 )
UDP_PORT=50000

declare -A PRIV PUB PID

cleanup() {
    echo "=== Cleaning up ==="
    for n in "${NODES[@]}"; do
        [[ -n "${PID[$n]:-}" ]] && sudo kill "${PID[$n]}" 2>/dev/null || true
        sudo ip netns delete "ns_$n" 2>/dev/null || true
        sudo ip link delete "vh_$n" 2>/dev/null || true
    done
    sudo ip link delete "$BRIDGE" 2>/dev/null || true
    rm -f daemon_*.log
    echo "Cleanup complete."
}
trap cleanup EXIT

echo "=== Building AraxMesh ==="
# The script runs as root (netns/TUN need it), but building as root uses
# root's rustup (often no default toolchain) and litters ./target with
# root-owned files. Build as the invoking user instead.
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    sudo -u "$SUDO_USER" env HOME="$USER_HOME" \
        PATH="$USER_HOME/.cargo/bin:$PATH" cargo build
else
    cargo build
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
    # veth: host end vh_$n on the bridge, namespace end veth0 inside ns_$n
    sudo ip link add "vh_$n" type veth peer name veth0 netns "ns_$n"
    sudo ip link set "vh_$n" master "$BRIDGE"
    sudo ip link set "vh_$n" up
    sudo ip netns exec "ns_$n" ip addr add "${UNDERLAY[$n]}/24" dev veth0
    sudo ip netns exec "ns_$n" ip link set veth0 up
    sudo ip netns exec "ns_$n" ip link set lo up
done

# Build the repeated --peer args for a node: every OTHER node, as
# "pubkey;underlay_endpoint;overlay_allowed_ip".
peer_args() {
    local self="$1" args=() m
    for m in "${NODES[@]}"; do
        [[ "$m" == "$self" ]] && continue
        args+=(--peer "${PUB[$m]};${UNDERLAY[$m]}:${UDP_PORT};${OVERLAY[$m]}")
    done
    printf '%s\n' "${args[@]}"
}

echo "=== Starting daemons ==="
for n in "${NODES[@]}"; do
    mapfile -t PARGS < <(peer_args "$n")
    sudo RUST_LOG=debug ip netns exec "ns_$n" ./target/debug/araxmesh \
        --tun-name arax0 \
        --tun-ip "${OVERLAY[$n]}" \
        --local-udp "${UNDERLAY[$n]}:${UDP_PORT}" \
        --private-key "${PRIV[$n]}" \
        "${PARGS[@]}" > "daemon_$n.log" 2>&1 &
    PID[$n]=$!
    echo "  ns_$n started (pid ${PID[$n]})"
done

# Give daemons time to bring up TUN interfaces; handshakes complete lazily
# on first traffic, so the ping loop below tolerates initial loss.
sleep 3

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
    echo "=== FAIL: $FAILURES pair(s) unreachable — daemon logs below ==="
    for n in "${NODES[@]}"; do
        echo "----- daemon_$n.log -----"
        cat "daemon_$n.log"
    done
    exit 1
fi
