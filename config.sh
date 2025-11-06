#!/usr/bin/env bash
# tc_auth.sh — clean / server / client setup for mirroring+drop via ifb0 on a given iface
# Usage:
#   sudo ./tc_auth.sh clean  [IFACE]
#   sudo ./tc_auth.sh server [IFACE] [SERVER_IP] [CLIENT_IP] [PORT]
#   sudo ./tc_auth.sh client [IFACE] [SERVER_IP] [CLIENT_IP] [PORT]
#
# Defaults match your ORBIT test:
#   IFACE=enp175s0f0np0, SERVER_IP=192.168.100.1, CLIENT_IP=192.168.100.2, PORT=9999
# If you’re on the older 192.168.200.x setup, just pass those instead.

set -euo pipefail

ROLE="${1:-}"
IFACE="${2:-enp175s0f0np0}"
SERVER_IP="${3:-192.168.100.1}"
CLIENT_IP="${4:-192.168.100.2}"
PORT="${5:-9999}"

SUDO="${SUDO:-sudo}"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo SUDO= $0 "$ROLE" "$IFACE" "$SERVER_IP" "$CLIENT_IP" "$PORT"
  fi
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

install_server() {
  echo "== SERVER filters (HOST=${SERVER_IP}, PEER=${CLIENT_IP}, IFACE=${IFACE}, PORT=${PORT}) =="

  # INGRESS (client -> server requests): mirror then drop
  $SUDO tc filter replace dev "$IFACE" ingress pref 100 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$CLIENT_IP" dst_ip "$SERVER_IP" dst_port "$PORT" \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  # EGRESS (server -> client replies, originals only DSCP=0): mirror then drop
  $SUDO tc filter replace dev "$IFACE" egress pref 200 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$SERVER_IP" src_port "$PORT" dst_ip "$CLIENT_IP" \
    ip_tos 0x00/0xFC \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  echo "-- Installed filters --"
  $SUDO tc -s filter show dev "$IFACE" ingress
  $SUDO tc -s filter show dev "$IFACE" egress
}

install_client() {
  echo "== CLIENT filters (HOST=${CLIENT_IP}, PEER=${SERVER_IP}, IFACE=${IFACE}, PORT=${PORT}) =="

  # EGRESS (client -> server requests, originals only DSCP=0): mirror then drop
  $SUDO tc filter replace dev "$IFACE" egress pref 100 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$CLIENT_IP" dst_ip "$SERVER_IP" dst_port "$PORT" \
    ip_tos 0x00/0xFC \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  # INGRESS (server -> client replies): mirror then drop
  $SUDO tc filter replace dev "$IFACE" ingress pref 200 protocol ip \
    flower skip_hw ip_proto udp \
    src_ip "$SERVER_IP" src_port "$PORT" dst_ip "$CLIENT_IP" \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  echo "-- Installed filters --"
  $SUDO tc -s filter show dev "$IFACE" ingress
  $SUDO tc -s filter show dev "$IFACE" egress
}

usage() {
  cat <<EOF
Usage:
  sudo $0 clean  [IFACE]
  sudo $0 server [IFACE] [SERVER_IP] [CLIENT_IP] [PORT]
  sudo $0 client [IFACE] [SERVER_IP] [CLIENT_IP] [PORT]

Defaults:
  IFACE=enp175s0f0np0  SERVER_IP=192.168.100.1  CLIENT_IP=192.168.100.2  PORT=9999

Examples:
  sudo $0 clean  enp175s0f0np0
  sudo $0 server enp175s0f0np0 192.168.100.1 192.168.100.2 9999
  sudo $0 client enp175s0f0np0 192.168.100.1 192.168.100.2 9999
EOF
}

main() {
  [[ -n "$ROLE" ]] || { usage; exit 2; }
  need_root
  case "$ROLE" in
    clean)
      clean_all
      ;;
    server)
      clean_all
      common_setup
      install_server
      ;;
    client)
      clean_all
      common_setup
      install_client
      ;;
    *)
      usage; exit 2;;
  esac
}

main "$@"