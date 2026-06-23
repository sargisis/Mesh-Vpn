#!/usr/bin/env bash
#
# AraxMesh soak test — Phase 6 (reliability / resilience).
#
# Runs a 3-node mesh (coordinator in ns_a + daemons in ns_a/ns_b/ns_c) under
# continuous traffic for a long duration, periodically injecting faults and
# verifying the network heals itself. Fault cycle (one fault per interval):
#
#   1. kill the coordinator, wait, restart it          (register/poll backoff)
#   2. drop a node's link, wait, bring it back          (session recovery / roaming)
#   3. kill a daemon, wait, restart it                  (rejoin from cold)
#
# Pass criteria, checked continuously:
#   - no daemon process ever dies unexpectedly (== never panics/crashes)
#   - no "panic" appears in any log
#   - after each fault + recovery grace period, the full ping matrix passes again
#
# Config via env:
#   SOAK_HOURS      total run time in hours          (default 48)
#   FAULT_INTERVAL  seconds between fault injections  (default 300)
#   RECOVERY_GRACE  seconds to heal before health chk (default 30)
#
# Requires sudo and root-capable netns. Tears everything down on exit.

set -euo pipefail

SOAK_HOURS="${SOAK_HOURS:-48}"
FAULT_INTERVAL="${FAULT_INTERVAL:-300}"
RECOVERY_GRACE="${RECOVERY_GRACE:-30}"

BRIDGE="araxbr0"
NODES=(a b c)
declare -A UNDERLAY=( [a]=192.168.100.1 [b]=192.168.100.2 [c]=192.168.100.3 )
declare -A OVERLAY=(  [a]=10.0.99.1      [b]=10.0.99.2      [c]=10.0.99.3 )
UDP_PORT=50000
COORD_URL="http://192.168.100.1:51820"
AUTH_KEY="test-secret-key"

declare -A PRIV PUB PID
declare -A PING_PID
COORDINATORD_PID=""

log() { echo "[$(date '+%F %T')] $*"; }

cleanup() {
    log "=== Cleaning up ==="
    for n in "${NODES[@]}"; do
        [[ -n "${PING_PID[$n]:-}" ]] && sudo kill "${PING_PID[$n]}" 2>/dev/null || true
        [[ -n "${PID[$n]:-}" ]] && sudo kill "${PID[$n]}" 2>/dev/null || true
        sudo ip netns delete "ns_$n" 2>/dev/null || true
        sudo ip link delete "vh_$n" 2>/dev/null || true
    done
    [[ -n "$COORDINATORD_PID" ]] && sudo kill "$COORDINATORD_PID" 2>/dev/null || true
    sudo ip link delete "$BRIDGE" 2>/dev/null || true
    log "Cleanup complete."
}
trap cleanup EXIT

# --- start helpers (also used to restart after a fault) ---------------------

start_coordinator() {
    sudo ip netns exec ns_a ./target/debug/coordinatord \
        --listen "0.0.0.0:51820" \
        --cidr "10.0.99.0/24" \
        --auth-key "$AUTH_KEY" >> coordinatord.log 2>&1 &
    COORDINATORD_PID=$!
    log "  coordinatord started (pid $COORDINATORD_PID)"
}

start_daemon() {
    local n="$1"
    sudo RUST_LOG=info ip netns exec "ns_$n" ./target/debug/araxmesh \
        --tun-name arax0 \
        --local-udp "${UNDERLAY[$n]}:${UDP_PORT}" \
        --private-key "${PRIV[$n]}" \
        --coordinator-url "$COORD_URL" \
        --auth-key "$AUTH_KEY" \
        --hostname "node-$n" \
        --public-endpoint "${UNDERLAY[$n]}:${UDP_PORT}" >> "daemon_$n.log" 2>&1 &
    PID[$n]=$!
    log "  ns_$n daemon started (pid ${PID[$n]})"
}

# --- health / crash checks --------------------------------------------------

check_no_crash() {
    local failed=0
    if ! sudo kill -0 "$COORDINATORD_PID" 2>/dev/null; then
        log "  CRASH: coordinatord (pid $COORDINATORD_PID) is dead unexpectedly"
        failed=1
    fi
    for n in "${NODES[@]}"; do
        if ! sudo kill -0 "${PID[$n]}" 2>/dev/null; then
            log "  CRASH: daemon ns_$n (pid ${PID[$n]}) is dead unexpectedly"
            failed=1
        fi
    done
    if grep -iq "panic" daemon_*.log coordinatord.log 2>/dev/null; then
        log "  CRASH: 'panic' found in a log:"
        grep -in "panic" daemon_*.log coordinatord.log 2>/dev/null | head -5
        failed=1
    fi
    return "$failed"
}

ping_matrix() {
    local failures=0
    for s in "${NODES[@]}"; do
        for d in "${NODES[@]}"; do
            [[ "$s" == "$d" ]] && continue
            if ! sudo ip netns exec "ns_$s" ping -c 2 -W 3 "${OVERLAY[$d]}" > /dev/null 2>&1; then
                failures=$((failures + 1))
            fi
        done
    done
    echo "$failures"
}

# --- setup ------------------------------------------------------------------

log "=== Soak test: ${SOAK_HOURS}h, fault every ${FAULT_INTERVAL}s, ${RECOVERY_GRACE}s recovery grace ==="
: > coordinatord.log
for n in "${NODES[@]}"; do : > "daemon_$n.log"; done

log "=== Building AraxMesh and Coordinator ==="
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    sudo -u "$SUDO_USER" env HOME="$USER_HOME" \
        PATH="$USER_HOME/.cargo/bin:$PATH" cargo build --bins
else
    cargo build --bins
fi

log "=== Generating Noise keypairs ==="
for n in "${NODES[@]}"; do
    OUT=$(./target/debug/araxmesh --gen-keys)
    PRIV[$n]=$(echo "$OUT" | awk '/Private Key/ {print $NF}')
    PUB[$n]=$(echo "$OUT"  | awk '/Public Key/  {print $NF}')
done

log "=== Creating bridge and namespaces ==="
sudo ip link add "$BRIDGE" type bridge
sudo ip link set "$BRIDGE" up
for n in "${NODES[@]}"; do
    sudo ip netns add "ns_$n"
    sudo ip link add "vh_$n" type veth peer name veth0 netns "ns_$n"
    sudo ip link set "vh_$n" master "$BRIDGE"
    sudo ip link set "vh_$n" up
    sudo ip netns exec "ns_$n" ip addr add "${UNDERLAY[$n]}/24" dev veth0
    sudo ip netns exec "ns_$n" ip link set veth0 up
    sudo ip netns exec "ns_$n" ip link set lo up
done

log "=== Starting coordinator and daemons ==="
start_coordinator
sleep 1
for n in "${NODES[@]}"; do start_daemon "$n"; sleep 1; done

log "=== Waiting for initial convergence ==="
sleep 12
init_fail=$(ping_matrix)
if [[ "$init_fail" -ne 0 ]]; then
    log "FAIL: mesh did not converge at startup ($init_fail unreachable pairs)"
    exit 1
fi
log "Initial ping matrix OK — starting continuous traffic + fault injection."

# Continuous background traffic: a slow ping flood between every pair.
for s in "${NODES[@]}"; do
    for d in "${NODES[@]}"; do
        [[ "$s" == "$d" ]] && continue
        sudo ip netns exec "ns_$s" ping -i 0.5 "${OVERLAY[$d]}" > /dev/null 2>&1 &
        PING_PID["${s}_${d}"]=$!
    done
done

# --- soak loop --------------------------------------------------------------

END=$(( $(date +%s) + SOAK_HOURS * 3600 ))
CYCLE=0
TOTAL_FAILS=0

while [[ "$(date +%s)" -lt "$END" ]]; do
    sleep "$FAULT_INTERVAL"
    CYCLE=$((CYCLE + 1))
    fault=$(( CYCLE % 3 ))

    case "$fault" in
        1)
            log "[cycle $CYCLE] FAULT: kill coordinator"
            sudo kill "$COORDINATORD_PID" 2>/dev/null || true
            sleep 5
            start_coordinator
            ;;
        2)
            victim="b"
            log "[cycle $CYCLE] FAULT: drop link for ns_$victim"
            sudo ip link set "vh_$victim" down
            sleep 5
            sudo ip link set "vh_$victim" up
            ;;
        0)
            victim="c"
            log "[cycle $CYCLE] FAULT: kill + restart daemon ns_$victim"
            sudo kill "${PID[$victim]}" 2>/dev/null || true
            sleep 5
            start_daemon "$victim"
            ;;
    esac

    log "[cycle $CYCLE] recovery grace ${RECOVERY_GRACE}s"
    sleep "$RECOVERY_GRACE"

    if ! check_no_crash; then
        log "FAIL: process crash / panic detected at cycle $CYCLE"
        exit 1
    fi

    fails=$(ping_matrix)
    if [[ "$fails" -ne 0 ]]; then
        log "[cycle $CYCLE] WARN: $fails unreachable pairs after recovery"
        TOTAL_FAILS=$((TOTAL_FAILS + 1))
        # one retry after a longer grace before declaring failure
        sleep "$RECOVERY_GRACE"
        fails=$(ping_matrix)
        if [[ "$fails" -ne 0 ]]; then
            log "FAIL: mesh did not self-heal at cycle $CYCLE ($fails unreachable pairs)"
            log "----- coordinatord.log (tail) -----"; tail -30 coordinatord.log
            for n in "${NODES[@]}"; do log "----- daemon_$n.log (tail) -----"; tail -30 "daemon_$n.log"; done
            exit 1
        fi
    fi
    log "[cycle $CYCLE] OK — no crash, mesh healthy"
done

log "=== PASS: survived ${SOAK_HOURS}h, $CYCLE fault cycles, no crash, mesh self-healed every time ==="
log "    (cycles needing a second recovery grace: $TOTAL_FAILS)"
