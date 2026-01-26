#!/usr/bin/env bash
# run_iperf_global.sh — one script for:
# - auth ON:   config.sh host + make run_both_* + iperf server OR sender sweep
# - auth OFF:  config.sh clean (no make) + iperf server OR sender sweep
#
# Stores results in timestamped folders.
# CSV is parsed from iperf3 "receiver" line (server-side stats via --get-server-output).
#
# Fixed params per request:
#   bandwidth = 100G
#   runs      = 32
#   duration  = 10s
#   sizes     = 128..8192

set -euo pipefail
IFS=$'\n\t'

# ---------- fixed test params ----------
IFACE="${IFACE:-enp175s0f0np0}"
PORT="${PORT:-9999}"
RUNS=32
DURATION_SEC=10
BANDWIDTH="100G"
SIZES=(128 256 512 1024 2048 4096 8192)
# --------------------------------------

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found"; exit 1; }; }
need_cmd ip
need_cmd iperf3
need_cmd python3
need_cmd date
need_cmd make

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

yn() {
  local prompt="$1" ans
  read -r -p "$prompt" ans || ans=""
  ans="$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "$ans" in y|yes) return 0 ;; *) return 1 ;; esac
}

parse_receiver_line_to_csv() {
  local raw_file="$1"
  python3 - "$raw_file" <<'PY'
import re, sys

path = sys.argv[1]
txt = open(path, 'r', errors='ignore').read().splitlines()

recv = None
for line in txt:
    if line.strip().endswith("receiver"):
        recv = line

if not recv:
    print(",,,,")
    sys.exit(0)

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
  if [[ ! -x ./config.sh ]]; then
    echo "ERROR: ./config.sh not found or not executable"
    exit 1
  fi
  echo "[auth_on] sudo ./config.sh host"
  sudo ./config.sh host

  if [[ ! -f Makefile ]]; then
    echo "ERROR: Makefile not found (needed to start af_reinject via make run_both_*)"
    exit 1
  fi

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

run_server() {
  local label="$1" host_ip="$2"
  local stamp; stamp="$(ts_folder)"
  local outdir="results/${label}/${IFACE}/iperf3/server/${stamp}_server_${host_ip}"
  mkdir -p "$outdir"

  {
    echo "role=server"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "fixed: runs=${RUNS} duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta.txt"

  local logfile="${outdir}/iperf3_server.log"
  echo
  echo "== SERVER =="
  echo "Logging to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

  sudo iperf3 -s -p "$PORT" --logfile "$logfile"
}

run_sender_sweep() {
  local label="$1" host_ip="$2" peer_ip="$3"
  local stamp; stamp="$(ts_folder)"
  local outdir="results/${label}/${IFACE}/iperf3/sweep/${stamp}_sender_${host_ip}_to_${peer_ip}"
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
    echo "fixed: runs=${RUNS} duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
    echo "sizes=${SIZES[*]}"
  } > "${outdir}/meta.txt"

  local csv="${outdir}/results.csv"
  : > "$csv"
  echo "timestamp,run_index,msg_size_bytes,bandwidth_arg,server_bitrate_bps,server_jitter_ms,server_lost,server_total,server_loss_percent" >> "$csv"

  echo
  echo "== SENDER sweep =="
  echo "Target: ${peer_ip}:${PORT}"
  echo "Fixed params: runs=${RUNS} duration=${DURATION_SEC}s bandwidth=${BANDWIDTH}"
  echo "Outdir: $outdir"
  echo

  for run in $(seq 1 "$RUNS"); do
    echo "=== Run ${run}/${RUNS} ==="
    for sz in "${SIZES[@]}"; do
      local logdir="${outdir}/run_${run}/sz_${sz}"
      mkdir -p "$logdir"
      local raw="${logdir}/iperf3_raw.txt"

      # IMPORTANT: --cport 9999 so ingress tc rule (src_port 9999) matches in auth mode.
      # We always keep it for consistency even when auth is off.
      if ! iperf3 -c "$peer_ip" -p "$PORT" -u \
          --cport "$PORT" \
          -l "$sz" -t "$DURATION_SEC" -b "$BANDWIDTH" \
          --get-server-output \
          >"$raw" 2>&1; then
        echo "[warn] iperf3 failed (run=$run size=$sz). See: $raw"
      fi

      local ts; ts="$(date +%s)"
      local parsed; parsed="$(parse_receiver_line_to_csv "$raw")"
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
  echo "Fixed: runs=$RUNS duration=${DURATION_SEC}s bandwidth=$BANDWIDTH sizes=${SIZES[*]}"
  echo

  local host_ip; host_ip="$(get_iface_ipv4 "$IFACE" || true)"
  [[ -n "$host_ip" ]] || { echo "ERROR: Could not detect IPv4 on $IFACE"; exit 1; }

  local peer_ip; peer_ip="$(auto_peer_from_host "$host_ip")"
  [[ -n "$peer_ip" ]] || { echo "ERROR: Host IP '$host_ip' not recognized for our 192.168.100.1/2 setup"; exit 1; }

  local role; role="$(ask_choice "Role? [server/sender]: " "server sender")"

  local label="auth_off"
  if yn "Auth enabled? [y/N]: "; then
    label="auth_on"
    # Auth ON means: set up tc + start reinjectors on THIS node
    auth_start_on_this_node "$host_ip"
  else
    # Auth OFF means: ensure everything is clean on THIS node
    auth_clean_only
  fi

  if [[ "$role" == "server" ]]; then
    run_server "$label" "$host_ip"
  else
    run_sender_sweep "$label" "$host_ip" "$peer_ip"
  fi
}

main "$@"
