#!/usr/bin/env bash
# run_iperf_global.sh (UDP)
# - auth ON:   config.sh host + make run_both_* + (bandwidth: iperf3) OR (rtt: udp echo)
# - auth OFF:  config.sh clean (no make) + (bandwidth: iperf3) OR (rtt: udp echo)
#
# One run folder per invocation (timestamped) containing all logs/results for that role.
# RUNS is user input (sender mode).
#
# BANDWIDTH TEST (unchanged structure):
#   results/<auth>/<iface>/iperf3/<ts>/...
#
# RTT TEST (new structure):
#   results/<auth>/<iface>/rtt/<ts>/results.csv
#   results/<auth>/<iface>/rtt/<ts>/run_<n>/sz_<size>/rtt_raw.txt

set -euo pipefail
IFS=$'\n\t'

# ---------- fixed test params ----------
IFACE="${IFACE:-enp175s0f0np0}"
PORT="${PORT:-9999}"

# bandwidth test params (unchanged)
DURATION_SEC=10
BANDWIDTH="100G"
SIZES=(128 256 512 1024 2048 4096 8192)

# rtt test params
RTT_TIMEOUT_SEC="${RTT_TIMEOUT_SEC:-0.5}"   # per-probe timeout (seconds)
# --------------------------------------

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found"; exit 1; }; }
need_cmd ip
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

# ---------------- BANDWIDTH (iperf3 UDP) helpers (UNCHANGED) ----------------
need_iperf3_if_bandwidth() {
  if [[ "${TEST_KIND:-}" == "bandwidth" ]]; then
    need_cmd iperf3
  fi
}

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
# --------------------------------------------------------------------------

# ---------------- RTT (UDP echo) helpers (NEW) ----------------
# Returns: rtt_ms,timeout_flag(0/1)
udp_rtt_probe_to_csv() {
  local host_ip="$1" peer_ip="$2" size="$3" raw_out="$4"
  python3 - "$host_ip" "$peer_ip" "$PORT" "$PORT" "$size" "$RTT_TIMEOUT_SEC" "$raw_out" <<'PY'
import secrets, socket, struct, sys, time

# argv: host_ip peer_ip dst_port src_port payload_size timeout_sec raw_out_path
host_ip = sys.argv[1]
peer_ip = sys.argv[2]
dst_port = int(sys.argv[3])
src_port = int(sys.argv[4])
payload_size = int(sys.argv[5])
timeout_s = float(sys.argv[6])
raw_path = sys.argv[7]

# 8-byte nonce + 8-byte timestamp so we can sanity-check echoes
nonce = secrets.token_bytes(8)
send_t_ns = time.perf_counter_ns()
hdr = nonce + struct.pack("!Q", send_t_ns)

if payload_size < len(hdr):
    payload = hdr[:payload_size]
else:
    payload = hdr + b"\x00" * (payload_size - len(hdr))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(timeout_s)

# bind fixed src port (PORT) so tc/af_reinject match keeps working
sock.bind((host_ip, src_port))

try:
    sock.sendto(payload, (peer_ip, dst_port))
    data, addr = sock.recvfrom(65535)
    recv_t_ns = time.perf_counter_ns()

    ok = (len(data) >= 8 and data[:8] == nonce)
    rtt_ms = (recv_t_ns - send_t_ns) / 1e6

    with open(raw_path, "w") as f:
        f.write("udp_rtt_probe\n")
        f.write(f"host_ip={host_ip}\npeer_ip={peer_ip}\n")
        f.write(f"src_port={src_port}\ndst_port={dst_port}\n")
        f.write(f"payload_size={payload_size}\n")
        f.write(f"timeout_s={timeout_s}\n")
        f.write(f"recv_from={addr}\n")
        f.write(f"recv_len={len(data)}\n")
        f.write(f"nonce_ok={ok}\n")
        f.write(f"rtt_ms={rtt_ms:.6f}\n")

    # CSV fields: rtt_ms,timeout_flag
    print(f"{rtt_ms:.6f},0")

except socket.timeout:
    with open(raw_path, "w") as f:
        f.write("udp_rtt_probe\n")
        f.write(f"host_ip={host_ip}\npeer_ip={peer_ip}\n")
        f.write(f"src_port={src_port}\ndst_port={dst_port}\n")
        f.write(f"payload_size={payload_size}\n")
        f.write(f"timeout_s={timeout_s}\n")
        f.write("timeout=1\n")
    print(",1")

finally:
    sock.close()
PY
}

run_rtt_server_mode() {
  local label="$1" host_ip="$2" stamp="$3"
  local outdir="results/${label}/${IFACE}/rtt/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=server"
    echo "test=rtt"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "UDP echo server for RTT"
  } > "${outdir}/meta_server.txt"

  local logfile="${outdir}/udp_echo_server.log"

  echo
  echo "== SERVER MODE (RTT / UDP echo) =="
  echo "Run folder: $outdir"
  echo "Logging server output to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

  python3 -u - "$host_ip" "$PORT" 2>&1 | tee "$logfile" <<'PY'
import socket, sys
host_ip = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host_ip, port))

print("udp_echo_server ready", flush=True)
print(f"listening {host_ip}:{port}", flush=True)

while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
PY
}

run_rtt_sender_mode() {
  local label="$1" host_ip="$2" peer_ip="$3" stamp="$4" runs="$5"
  local outdir="results/${label}/${IFACE}/rtt/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=sender"
    echo "test=rtt"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "peer_ip=${peer_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "UDP RTT via echo"
    echo "runs=${runs}"
    echo "sizes=${SIZES[*]}"
    echo "timeout_sec=${RTT_TIMEOUT_SEC}"
  } > "${outdir}/meta_sender.txt"

  local csv="${outdir}/results.csv"
  : > "$csv"
  echo "timestamp,run_index,msg_size_bytes,rtt_ms,timeout" >> "$csv"

  echo
  echo "== SENDER MODE (RTT / UDP echo) =="
  echo "Run folder: $outdir"
  echo "Target: ${peer_ip}:${PORT}"
  echo "Params: runs=${runs} timeout=${RTT_TIMEOUT_SEC}s"
  echo

  for run in $(seq 1 "$runs"); do
    echo "=== Run ${run}/${runs} ==="
    for sz in "${SIZES[@]}"; do
      local logdir="${outdir}/run_${run}/sz_${sz}"
      mkdir -p "$logdir"

      local raw="${logdir}/rtt_raw.txt"
      local ts; ts="$(date +%s)"

      local parsed
      parsed="$(udp_rtt_probe_to_csv "$host_ip" "$peer_ip" "$sz" "$raw" || true)"
      [[ -n "${parsed:-}" ]] || parsed=",1"

      echo "${ts},${run},${sz},${parsed}" >> "$csv"
    done
  done

  echo
  echo "Done."
  echo "CSV: $csv"
  echo "Raw logs: $outdir/run_*/sz_*/rtt_raw.txt"
}
# --------------------------------------------------------------------------

kill_all_iperf3() {
  echo "[prep] Killing any running iperf3 / udp_echo_server and freeing port $PORT (best effort)..."

  sudo pkill -9 iperf3 2>/dev/null || true
  sudo pkill -f udp_echo_server 2>/dev/null || true

  if command -v fuser >/dev/null 2>&1; then
    sudo fuser -k -n tcp "$PORT" 2>/dev/null || true
    sudo fuser -k -n udp "$PORT" 2>/dev/null || true
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

# ---------------- BANDWIDTH MODE (UNCHANGED STRUCTURE) ----------------
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
  echo "== SERVER MODE (UDP bandwidth / iperf3) =="
  echo "Run folder: $outdir"
  echo "Logging server output to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

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
  echo "== SENDER MODE (UDP bandwidth / iperf3) =="
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
# -----------------------------------------------------------------------

main() {
  local role label stamp runs host_ip peer_ip

  echo "IFACE=$IFACE PORT=$PORT"
  echo "UDP sizes=${SIZES[*]}"
  echo

  host_ip="$(get_iface_ipv4 "$IFACE" || true)"
  [[ -n "$host_ip" ]] || { echo "ERROR: Could not detect IPv4 on $IFACE"; exit 1; }

  peer_ip="$(auto_peer_from_host "$host_ip")"
  [[ -n "$peer_ip" ]] || { echo "ERROR: Host IP '$host_ip' not recognized for our 192.168.100.1/2 setup"; exit 1; }

  TEST_KIND="$(ask_choice "Test? [bandwidth/rtt]: " "bandwidth rtt")"
  role="$(ask_choice "Role? [server/sender]: " "server sender")"

  label="auth_off"
  if yn "Auth enabled? [y/N]: "; then label="auth_on"; fi

  stamp="$(ts_folder)"
  echo "Run folder timestamp: $stamp"
  echo

  runs=1
  if [[ "$role" == "sender" ]]; then
    if [[ "$TEST_KIND" == "bandwidth" ]]; then
      runs="$(ask_int "How many runs per msg_size?" "32")"
    else
      runs="$(ask_int "How many RTT runs per msg_size?" "32")"
    fi
  fi

  need_iperf3_if_bandwidth
  kill_all_iperf3

  if [[ "$label" == "auth_on" ]]; then
    auth_start_on_this_node "$host_ip"
  else
    auth_clean_only
  fi

  if [[ "$TEST_KIND" == "bandwidth" ]]; then
    # bandwidth folder structure unchanged
    if [[ "$role" == "server" ]]; then
      run_server_mode "$label" "$host_ip" "$stamp"
    else
      run_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs"
    fi
    exit 0
  fi

  # RTT mode
  if [[ "$role" == "server" ]]; then
    run_rtt_server_mode "$label" "$host_ip" "$stamp"
  else
    run_rtt_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs"
  fi
}

main "$@"
