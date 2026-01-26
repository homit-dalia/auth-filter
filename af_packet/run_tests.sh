#!/usr/bin/env bash
# run_iperf_global.sh (TCP)
# - auth ON:   config.sh host + (override tc filters to TCP) + make run_both_* + iperf3 server OR sender sweep
# - auth OFF:  config.sh clean (no make) + iperf3 server OR sender sweep
#
# One run folder per invocation (timestamped) containing all logs/results for that role.
# RUNS is user input.
#
# TCP notes:
# - iperf3 TCP has no jitter/loss. We log server-side Transfer + Bitrate from the SERVER "receiver" line
#   using --get-server-output.
# - BANDWIDTH is kept only as a label (iperf3 TCP ignores -b).
#
# Fixed:
#   duration  = 10s
#   sizes     = 128..8192
#   bandwidth label = 100G (not used by TCP)

set -euo pipefail
IFS=$'\n\t'

# ---------- fixed test params ----------
IFACE="${IFACE:-enp175s0f0np0}"
PORT="${PORT:-9999}"
DURATION_SEC=10
BANDWIDTH_LABEL="100G"                 # TCP ignores -b; kept for labeling
SIZES=(128 256 512 1024 2048 4096 8192)
PARALLEL_STREAMS="${PARALLEL_STREAMS:-1}"  # TCP: increase (e.g., 8/16) to try to hit higher rates
# --------------------------------------

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found"; exit 1; }; }
need_cmd ip
need_cmd iperf3
need_cmd python3
need_cmd date

ts_folder() { date +"%Y%m%d_%H%M%S"; }

get_iface_ipv4() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

auto_peer_from_host() {
  local host="$1"
  case "$host" in
    192.168.100.1) echo "192.168.100.2" ;;
    192.168.100.2) echo "192.168.100.1" ;;
    *) echo "" ;;
  esac
}

ask_choice() {
  local prompt="$1" valid="$2" ans
  while true; do
    read -r -p "$prompt" ans || ans=""
    ans="$(echo "$ans" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ -n "$ans" ]] || continue
    if echo " $valid " | grep -q " $ans "; then
      echo "$ans"
      return 0
    fi
    echo "Invalid. Choose one of: $valid"
  done
}

ask_int() {
  local prompt="$1" def="$2" ans
  read -r -p "$prompt [$def]: " ans || ans=""
  ans="${ans:-$def}"
  if ! [[ "$ans" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: expected positive integer, got '$ans'"
    exit 1
  fi
  echo "$ans"
}

yn() {
  local prompt="$1" ans
  read -r -p "$prompt" ans || ans=""
  ans="$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "$ans" in y|yes) return 0 ;; *) return 1 ;; esac
}

# Parse TCP receiver line from server output:
# Returns: transfer_bytes,bitrate_bps
parse_tcp_receiver_to_csv() {
  local raw_file="$1"
  python3 - "$raw_file" <<'PY'
import re, sys

path = sys.argv[1]
lines = open(path, 'r', errors='ignore').read().splitlines()

recv = None
for line in lines:
    if line.strip().endswith("receiver"):
        recv = line

if not recv:
    print(",")  # transfer_bytes,bitrate_bps
    sys.exit(0)

# Typical TCP receiver summary:
# [  5]   0.00-10.00  sec  2.68 GBytes  2.30 Gbits/sec                  receiver
m = re.search(r'\s([\d.]+)\s*([KMG]?Bytes)\s+([\d.]+)\s*([KMG]?bits/sec)\s+.*receiver$', recv)
if not m:
    print(",")
    sys.exit(0)

t_val = float(m.group(1))
t_unit = m.group(2)
b_val = float(m.group(3))
b_unit = m.group(4)

t_mul = 1.0
if t_unit.startswith("K"): t_mul = 1e3
elif t_unit.startswith("M"): t_mul = 1e6
elif t_unit.startswith("G"): t_mul = 1e9

b_mul = 1.0
if b_unit.startswith("K"): b_mul = 1e3
elif b_unit.startswith("M"): b_mul = 1e6
elif b_unit.startswith("G"): b_mul = 1e9

transfer_bytes = t_val * t_mul
bitrate_bps = b_val * b_mul
print(f"{transfer_bytes},{bitrate_bps}")
PY
}

auth_clean_only() {
  if [[ -x ./config.sh ]]; then
    echo "[auth_off] sudo ./config.sh clean"
    sudo ./config.sh clean
  else
    echo "[warn] ./config.sh not found/executable; skipping tc clean."
  fi
  echo "[auth_off] sudo pkill -f af_reinject (best effort)"
  sudo pkill -f af_reinject 2>/dev/null || true
}

# IMPORTANT: your config.sh installs UDP flower filters.
# For TCP tests, we override those tc filters to ip_proto tcp.
install_tcp_filters_override() {
  local host_ip="$1"
  local peer_ip="$2"

  echo "[auth_on] Overriding tc filters to TCP (port ${PORT}) on ${IFACE}"
  echo "          HOST_IP=${host_ip} PEER_IP=${peer_ip}"

  # EGRESS (HOST -> PEER): mirror+drop ONLY DSCP=0 originals
  sudo tc filter replace dev "$IFACE" egress pref 100 protocol ip \
    flower skip_hw ip_proto tcp \
    src_ip "$host_ip" dst_ip "$peer_ip" dst_port "$PORT" \
    ip_tos 0x00/0xFC \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  # INGRESS (PEER -> HOST): mirror+drop ALL (captures reinjected DSCP=EF too)
  sudo tc filter replace dev "$IFACE" ingress pref 200 protocol ip \
    flower skip_hw ip_proto tcp \
    src_ip "$peer_ip" src_port "$PORT" dst_ip "$host_ip" \
    action mirred egress mirror dev ifb0 pipe \
    action gact drop

  echo "[auth_on] tc filters (ingress):"
  sudo tc -s filter show dev "$IFACE" ingress || true
  echo "[auth_on] tc filters (egress):"
  sudo tc -s filter show dev "$IFACE" egress || true
}

auth_start_on_this_node() {
  local host_ip="$1"
  local peer_ip="$2"

  [[ -x ./config.sh ]] || { echo "ERROR: ./config.sh not found or not executable"; exit 1; }

  echo "[auth_on] sudo ./config.sh host"
  sudo ./config.sh host

  # Override UDP tc rules with TCP ones
  install_tcp_filters_override "$host_ip" "$peer_ip"

  [[ -f makefile ]] || { echo "ERROR: Makefile not found (needed to start af_reinject via make run_both_*)"; exit 1; }
  need_cmd make

  if [[ "$host_ip" == "192.168.100.1" ]]; then
    echo "[auth_on] make run_both_bodhi"
    make run_both_bodhi
  elif [[ "$host_ip" == "192.168.100.2" ]]; then
    echo "[auth_on] make run_both_banyan"
    make run_both_banyan
  else
    echo "ERROR: host_ip '$host_ip' not recognized for our setup"
    exit 1
  fi
}

server_marker_capture() {
  # Capture a few packets on server to "mark" traffic windows (TCP).
  local outdir="$1"
  local run="$2"
  local sz="$3"

  need_cmd tcpdump

  local mdir="${outdir}/markers"
  mkdir -p "$mdir"

  local pcap="${mdir}/run_${run}_sz_${sz}.pcap"
  local txt="${mdir}/run_${run}_sz_${sz}.txt"

  sudo timeout 3 tcpdump -ni "$IFACE" tcp port "$PORT" -c 20 -w "$pcap" >/dev/null 2>&1 || true
  sudo tcpdump -nn -tt -vv -r "$pcap" > "$txt" 2>/dev/null || true
}

run_server_mode() {
  local label="$1" host_ip="$2"
  local stamp="$3"
  local outdir="results/${label}/${IFACE}/iperf3/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=server"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "TCP mode"
    echo "fixed: duration=${DURATION_SEC}s bandwidth_label=${BANDWIDTH_LABEL}"
    echo "parallel_streams=${PARALLEL_STREAMS}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta_server.txt"

  local logfile="${outdir}/iperf3_server.log"

  echo
  echo "== SERVER MODE (TCP) =="
  echo "Run folder: $outdir"
  echo "Logging server output to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

  sudo iperf3 -s -p "$PORT" --logfile "$logfile"
}

run_sender_mode() {
  local label="$1" host_ip="$2" peer_ip="$3"
  local stamp="$4"
  local runs="$5"
  local outdir="results/${label}/${IFACE}/iperf3/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=sender"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "peer_ip=${peer_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "TCP mode"
    echo "fixed: duration=${DURATION_SEC}s bandwidth_label=${BANDWIDTH_LABEL}"
    echo "runs=${runs}"
    echo "parallel_streams=${PARALLEL_STREAMS}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta_sender.txt"

  local csv="${outdir}/results.csv"
  : > "$csv"
  echo "timestamp,run_index,msg_size_bytes,parallel_streams,duration_sec,transfer_bytes,server_bitrate_bps" >> "$csv"

  echo
  echo "== SENDER MODE (TCP) =="
  echo "Run folder: $outdir"
  echo "Target: ${peer_ip}:${PORT}"
  echo "Params: runs=${runs} duration=${DURATION_SEC}s parallel=${PARALLEL_STREAMS} (bandwidth_label=${BANDWIDTH_LABEL}, TCP ignores -b)"
  echo

  for run in $(seq 1 "$runs"); do
    echo "=== Run ${run}/${runs} ==="
    for sz in "${SIZES[@]}"; do
      local logdir="${outdir}/run_${run}/sz_${sz}"
      mkdir -p "$logdir"
      local raw="${logdir}/iperf3_raw.txt"

      {
        echo "cmd: iperf3 -c $peer_ip -p $PORT --cport $PORT -l $sz -t $DURATION_SEC -P $PARALLEL_STREAMS --get-server-output"
        echo "start_ts: $(date +%s)"
      } > "${logdir}/meta.txt"

      # TCP client -> server. Keep --cport=PORT to keep 9999 source port for tc ingress match.
      if ! iperf3 -c "$peer_ip" -p "$PORT" \
          --cport "$PORT" \
          -l "$sz" -t "$DURATION_SEC" -P "$PARALLEL_STREAMS" \
          --get-server-output \
          >"$raw" 2>&1; then
        echo "[warn] iperf3 failed (run=$run size=$sz). See: $raw"
      fi

      local ts; ts="$(date +%s)"
      local parsed; parsed="$(parse_tcp_receiver_to_csv "$raw")"  # transfer_bytes,bitrate_bps
      echo "${ts},${run},${sz},${PARALLEL_STREAMS},${DURATION_SEC},${parsed}" >> "$csv"
    done
  done

  echo
  echo "Done."
  echo "CSV: $csv"
  echo "Raw logs: $outdir/run_*/sz_*/iperf3_raw.txt"
}

kill_all_iperf3() {
  echo "[prep] Killing any running iperf3 (best effort)..."

  # Kill any iperf3 process
  sudo pkill -9 iperf3 2>/dev/null || true

  # Kill anything holding our port (TCP)
  if command -v fuser >/dev/null 2>&1; then
    sudo fuser -k -n tcp "$PORT" 2>/dev/null || true
  fi

  # Fallback: lsof
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(sudo lsof -t -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "${pids:-}" ]]; then
      echo "[prep] Killing LISTEN pids on tcp/$PORT: $pids"
      sudo kill -9 $pids 2>/dev/null || true
    fi
  fi

  echo "[prep] Done. Current listeners on tcp/$PORT:"
  sudo ss -ltnp "( sport = :$PORT )" 2>/dev/null || true
}


main() {
  echo "IFACE=$IFACE PORT=$PORT"
  echo "TCP: duration=${DURATION_SEC}s bandwidth_label=${BANDWIDTH_LABEL} parallel=${PARALLEL_STREAMS} sizes=${SIZES[*]}"
  echo

  local host_ip; host_ip="$(get_iface_ipv4 "$IFACE" || true)"
  [[ -n "$host_ip" ]] || { echo "ERROR: Could not detect IPv4 on $IFACE"; exit 1; }

  local peer_ip; peer_ip="$(auto_peer_from_host "$host_ip")"
  [[ -n "$peer_ip" ]] || { echo "ERROR: Host IP '$host_ip' not recognized for our 192.168.100.1/2 setup"; exit 1; }

  local role; role="$(ask_choice "Role? [server/sender]: " "server sender")"
  local label="auth_off"
  if yn "Auth enabled? [y/N]: "; then label="auth_on"; fi

  local stamp; stamp="$(ts_folder)"
  echo "Run folder timestamp: $stamp"
  echo

  local runs=1
  if [[ "$role" == "sender" ]]; then
    runs="$(ask_int "How many runs per msg_size?" "32")"
  fi

  kill_all_iperf3

  if [[ "$label" == "auth_on" ]]; then
    auth_start_on_this_node "$host_ip" "$peer_ip"
  else
    auth_clean_only
  fi

  if [[ "$role" == "server" ]]; then
    run_server_mode "$label" "$host_ip" "$stamp"
    exit 0
  fi

  run_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs"
}

main "$@"
