#!/usr/bin/env bash
# tc_auth.sh — clean / host setup for bidirectional mirroring+drop via ifb0 on a given iface
#
# Usage:
#   sudo ./tc_auth.sh clean
#   sudo ./tc_auth.sh host
#
# Auto-detects HOST_IP from IFACE (default enp175s0f0np0) and sets PEER_IP
# assuming our setup:
#   node1-4: 192.168.100.1
#   node1-6: 192.168.100.2
#
# Overrides (optional):
#   IFACE=enp175s0f0np0 PORT=9999 PEER_IP=192.168.100.2 sudo ./tc_auth.sh host

set -euo pipefail

ROLE="${1:-}"
SUDO="${SUDO:-sudo}"

# Defaults (can be overridden via env)
IFACE="${IFACE:-enp175s0f0np0}"
PORT="${PORT:-9999}"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo SUDO= $0 "$ROLE"
  fi
}

get_iface_ipv4() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

auto_pick_ips() {
  HOST_IP="$(get_iface_ipv4 "$IFACE" || true)"
  if [[ -z "${HOST_IP:-}" ]]; then
    echo "[error] Could not detect IPv4 address on IFACE=$IFACE"
    echo "        Run: ip -4 -o addr show dev $IFACE"
    exit 1
  fi

  # Allow explicit override
  if [[ -n "${PEER_IP:-}" ]]; then
    return
  fi

  case "$HOST_IP" in
    192.168.100.1) PEER_IP="192.168.100.2" ;;
    192.168.100.2) PEER_IP="192.168.100.1" ;;
    *)
      echo "[error] HOST_IP=$HOST_IP not recognized for our setup."
      echo "        Set PEER_IP manually: PEER_IP=... sudo ./tc_auth.sh host"
      exit 1
      ;;
  esac
}

clean_all() {
  echo "== CLEAN on ${IFACE} =="
  $SUDO pkill -f af_reinject 2>/dev/null || true

  $SUDO tc filter del dev "$IFACE" egress  2>/dev/null || true
  $SUDO tc filter del dev "$IFACE" ingress 2>/dev/null || true
  $SUDO tc qdisc  del dev "$IFACE" clsact 2>/dev/null || true

  $SUDO ip link set ifb0 down  2>/dev/null || true
  $SUDO ip link del ifb0       2>/dev/null || true

  $SUDO ip link set auth0 down 2>/dev/null || true
  $SUDO ip link del auth0      2>/dev/null || true

  echo "-- Remaining filters --"
  $SUDO tc -s filter show dev "$IFACE" egress  || true
  $SUDO tc -s filter show dev "$IFACE" ingress || true
}

common_setup() {
  echo "== COMMON setup on ${IFACE} (ifb0 + clsact + TUN) =="
  $SUDO modprobe ifb act_mirred act_gact sch_clsact cls_flower || true

  ip link show ifb0 >/dev/null 2>&1 || $SUDO ip link add ifb0 type ifb
  $SUDO ip link set ifb0 up

  $SUDO tc qdisc add dev "$IFACE" clsact 2>/dev/null || true

  # TUN for verified delivery
  ip link show auth0 >/dev/null 2>&1 || $SUDO ip tuntap add dev auth0 mode tun
  $SUDO ip link set auth0 up
  $SUDO sysctl -q -w net.ipv4.conf.auth0.accept_local=1
  $SUDO sysctl -q -w net.ipv4.conf.auth0.rp_filter=0
  $SUDO sysctl -q -w net.ipv4.conf.all.rp_filter=0
  $SUDO sysctl -q -w net.ipv4.conf.default.rp_filter=0
}

install_host_bidirectional() {
  echo "== HOST bidirectional filters =="
  echo "   IFACE=${IFACE} PORT=${PORT}"
  echo "   HOST_IP=${HOST_IP} PEER_IP=${PEER_IP}"

  # EGRESS (HOST -> PEER): mirror+drop ONLY DSCP=0 originals
  $SUDO tc filter replace dev "$IFACE" egress pref 100 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$HOST_IP" dst_ip "$PEER_IP" dst_port "$PORT" \
    ip_tos 0x00/0xFC \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  # INGRESS (PEER -> HOST): mirror+drop ALL (captures reinjected DSCP=EF too)
  $SUDO tc filter replace dev "$IFACE" ingress pref 200 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$PEER_IP" src_port "$PORT" dst_ip "$HOST_IP" \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  echo "-- Installed filters --"
  $SUDO tc -s filter show dev "$IFACE" ingress
  $SUDO tc -s filter show dev "$IFACE" egress
}

usage() {
  cat <<EOF
Usage:
  sudo $0 clean
  sudo $0 host

Env overrides (optional):
  IFACE=enp175s0f0np0 PORT=9999 PEER_IP=192.168.100.2 sudo $0 host
EOF
}

main() {
  [[ -n "$ROLE" ]] || { usage; exit 2; }
  need_root

  case "$ROLE" in
    clean)
      clean_all
      ;;
    host)
      auto_pick_ips
      clean_all
      common_setup
      install_host_bidirectional
      ;;
    *)
      usage; exit 2;;
  esac
}

main "$@"
