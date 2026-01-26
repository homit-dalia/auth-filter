#!/usr/bin/env bash
# run_iperf_global.sh (UDP)
# - auth ON:   config.sh host + make run_both_* + iperf3 server OR sender sweep
# - auth OFF:  config.sh clean (no make) + iperf3 server OR sender sweep
#
# One run folder per invocation (timestamped) containing all logs/results for that role.
# RUNS is user input (sender mode).
#
# UDP notes:
# - iperf3 UDP reports jitter/loss. We log SERVER "receiver" line stats using --get-server-output.
# - We keep --cport=$PORT so tc ingress match (src_port $PORT) can work in auth mode.
#
# Fixed:
#   duration  = 10s
#   bandwidth = 100G
#   sizes     = 128..8192

set -euo pipefail
IFS=$'\n\t'

# ---------- fixed test params ----------
IFACE="${IFACE:-enp175s0f0np0}"
PORT="${PORT:-9999}"
DURATION_SEC=10
BANDWIDTH="100G"
SIZES=(128 256 512 1024 2048 4096 8192)
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

# UDP receiver line parse -> returns:
# server_bitrate_bps,server_jitter_ms,server_lost,server_total,server_loss_percent
parse_udp_receiver_line_to_csv() {
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
    print(",,,,")
    sys.exit(0)

# Example UDP receiver summary:
# [  6]   0.00-10.00  sec  2.68 GBytes  2.30 Gbits/sec  0.001 ms  157940/2970119 (5.3%)  receiver
m = re.search(r'\s([\d.]+)\s*([KMG]?bits/sec)\s+([\d.]+)\s*ms\s+(\d+)\s*/\s*(\d+)\s*\(([\d.]+)%\)', recv)
if not m:
    print(",,,,")
    sys.exit(0)

val = float(m.group(1))
unit = m.group(2)
jitter = m.group(3)
lost = m.group(4)
total = m.group(5)
loss = m.group(6)

mul = 1.0
if unit.startswith("K"): mul = 1e3
elif unit.startswith("M"): mul = 1e6
elif unit.startswith("G"): mul = 1e9

bps = val * mul
print(f"{bps},{jitter},{lost},{total},{loss}")
PY
}

kill_all_iperf3() {
  echo "[prep] Killing any running iperf3 and freeing port $PORT (best effort)..."

  sudo pkill -9 iperf3 2>/dev/null || true

  if command -v fuser >/dev/null 2>&1; then
    sudo fuser -k -n tcp "$PORT" 2>/dev/null || true
    sudo fuser -k -n udp "$PORT" 2>/dev/null || true
  fi

  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(sudo lsof -t -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "${pids:-}" ]]; then
      echo "[prep] Killing LISTEN pids on tcp/$PORT: $pids"
      sudo kill -9 $pids 2>/dev/null || true
    fi
  fi

  echo "[prep] Current listeners on :$PORT (tcp/udp):"
  sudo ss -ltnp "( sport = :$PORT )" 2>/dev/null || true
  sudo ss -lunp "( sport = :$PORT )" 2>/dev/null || true
  echo "[prep] Done."
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

auth_start_on_this_node() {
  local host_ip="$1"

  [[ -x ./config.sh ]] || { echo "ERROR: ./config.sh not found or not executable"; exit 1; }

  echo "[auth_on] sudo ./config.sh host"
  sudo ./config.sh host

  # Your repo uses lowercase makefile
  [[ -f makefile ]] || { echo "ERROR: makefile not found (needed to start af_reinject via make run_both_*)"; exit 1; }
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

start_server_pcap_capture() {
  local outdir="$1"
  local pcap="${outdir}/udp_traffic.pcap"
  local pidfile="${outdir}/tcpdump.pid"

  if ! command -v tcpdump >/dev/null 2>&1; then
    echo "[server] tcpdump not found; skipping pcap capture."
    return 0
  fi

  echo "[server] Starting tcpdump capture -> $pcap"
  # Capture UDP port traffic on IFACE; keep it lightweight.
  sudo tcpdump -ni "$IFACE" "udp port $PORT" -w "$pcap" >/dev/null 2>&1 &
  echo $! | sudo tee "$pidfile" >/dev/null
}

stop_server_pcap_capture() {
  local outdir="$1"
  local pidfile="${outdir}/tcpdump.pid"

  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(sudo cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]]; then
      echo "[server] Stopping tcpdump pid=$pid"
      sudo kill "$pid" 2>/dev/null || true
    fi
  fi
}

run_server_mode() {
  local label="$1" host_ip="$2" stamp="$3"
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
    echo "UDP mode"
    echo "fixed: duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta_server.txt"

  local logfile="${outdir}/iperf3_server.log"

  echo
  echo "== SERVER MODE (UDP) =="
  echo "Run folder: $outdir"
  echo "Logging server output to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

  start_server_pcap_capture "$outdir"
  trap 'stop_server_pcap_capture "$outdir"' EXIT

  sudo iperf3 -s -p "$PORT" --logfile "$logfile"
}

run_sender_mode() {
  local label="$1" host_ip="$2" peer_ip="$3" stamp="$4" runs="$5"
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
    echo "UDP mode"
    echo "fixed: duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
    echo "runs=${runs}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta_sender.txt"

  local csv="${outdir}/results.csv"
  : > "$csv"
  echo "timestamp,run_index,msg_size_bytes,bandwidth_arg,server_bitrate_bps,server_jitter_ms,server_lost,server_total,server_loss_percent" >> "$csv"

  echo
  echo "== SENDER MODE (UDP) =="
  echo "Run folder: $outdir"
  echo "Target: ${peer_ip}:${PORT}"
  echo "Params: runs=${runs} duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
  echo

  for run in $(seq 1 "$runs"); do
    echo "=== Run ${run}/${runs} ==="
    for sz in "${SIZES[@]}"; do
      local logdir="${outdir}/run_${run}/sz_${sz}"
      mkdir -p "$logdir"
      local raw="${logdir}/iperf3_raw.txt"

      {
        echo "cmd: iperf3 -c $peer_ip -p $PORT -u --cport $PORT -l $sz -t $DURATION_SEC -b $BANDWIDTH --get-server-output"
        echo "start_ts: $(date +%s)"
      } > "${logdir}/meta.txt"

      if ! iperf3 -c "$peer_ip" -p "$PORT" -u \
          --cport "$PORT" \
          -l "$sz" -t "$DURATION_SEC" -b "$BANDWIDTH" \
          --get-server-output \
          >"$raw" 2>&1; then
        echo "[warn] iperf3 failed (run=$run size=$sz). See: $raw"
      fi

      local ts; ts="$(date +%s)"
      local parsed; parsed="$(parse_udp_receiver_line_to_csv "$raw")"
      echo "${ts},${run},${sz},${BANDWIDTH},${parsed}" >> "$csv"
    done
  done

  echo
  echo "Done."
  echo "CSV: $csv"
  echo "Raw logs: $outdir/run_*/sz_*/iperf3_raw.txt"
}

main() {
  echo "IFACE=$IFACE PORT=$PORT"
  echo "UDP: duration=${DURATION_SEC}s bandwidth=$BANDWIDTH sizes=${SIZES[*]}"
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
    auth_start_on_this_node "$host_ip"
  else
    auth_clean_only
  fi

  if [[ "$role" == "server" ]]; then
    run_server_mode "$label" "$host_ip" "$stamp"
  else
    run_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs"
  fi
}

main "$@"
