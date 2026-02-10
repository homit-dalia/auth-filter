#!/usr/bin/env bash
# run_iperf_global.sh (UDP)
# - auth ON:   config.sh host + make run_both_* + (bandwidth: iperf3) OR (rtt: sockperf)
# - auth OFF:  config.sh clean (no make) + (bandwidth: iperf3) OR (rtt: sockperf)
#
# One run folder per invocation (timestamped) containing all logs/results for that role.
# RUNS is user input (sender mode).
#
# BANDWIDTH TEST (unchanged structure):
#   results/<auth>/<iface>/iperf3/<ts>/...
#
# RTT TEST (sockperf, structure unchanged):
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

# RTT + bandwidth sizes (updated per request)
SIZES=(32 128 512 1024 2048 4096 8192)

# RTT sockperf params
SOCKPERF_TIME_SEC=10
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

ask_int_allow_zero() {
  # 0 means "no override"
  local prompt="$1" def="$2" ans
  read -r -p "$prompt [$def]: " ans || ans=""
  ans="${ans:-$def}"
  if ! [[ "$ans" =~ ^[0-9]+$ ]]; then
    echo "ERROR: expected integer >= 0, got '$ans'"
    exit 1
  fi
  echo "$ans"
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

# ---------------- RTT (sockperf full RTT) helpers (NEW) ----------------
need_sockperf_if_rtt() {
  if [[ "${TEST_KIND:-}" == "rtt" ]]; then
    need_cmd sockperf
  fi
}

# Parse sockperf output to CSV fields:
# rtt_min_us,rtt_avg_us,rtt_p50_us,rtt_p99_us,rtt_max_us,timeout_flag
#
# We treat "timeout_flag" as 1 if the command failed or we couldn't parse.
parse_sockperf_to_csv() {
  local raw_file="$1"
  python3 - "$raw_file" <<'PY'
import re, sys

p = sys.argv[1]
txt = open(p, "r", errors="ignore").read()

# Common sockperf ping-pong summary patterns vary by version.
# We'll try multiple regexes for min/avg/max and percentiles.
def f(s):
    try:
        return float(s)
    except:
        return None

min_v = avg_v = max_v = None
p50 = p99 = None

# Pattern A: "min/avg/max = X / Y / Z"
m = re.search(r'\bmin\s*/\s*avg\s*/\s*max\s*=\s*([\d.]+)\s*/\s*([\d.]+)\s*/\s*([\d.]+)', txt, re.I)
if m:
    min_v, avg_v, max_v = map(f, m.groups())

# Pattern B: separate lines like "min: X" "avg: Y" "max: Z"
if min_v is None:
    m = re.search(r'\bmin(?:imum)?\s*[:=]\s*([\d.]+)', txt, re.I)
    if m: min_v = f(m.group(1))
if avg_v is None:
    m = re.search(r'\bavg(?:erage)?\s*[:=]\s*([\d.]+)', txt, re.I)
    if m: avg_v = f(m.group(1))
if max_v is None:
    m = re.search(r'\bmax(?:imum)?\s*[:=]\s*([\d.]+)', txt, re.I)
    if m: max_v = f(m.group(1))

# Percentiles: "50.000%  X" or "percentile 50.00: X"
m = re.search(r'\b50(?:\.0+)?%\s+([\d.]+)', txt)
if m: p50 = f(m.group(1))
if p50 is None:
    m = re.search(r'\b(?:p50|50th)\b.*?([\d.]+)', txt, re.I)
    if m: p50 = f(m.group(1))

m = re.search(r'\b99(?:\.0+)?%\s+([\d.]+)', txt)
if m: p99 = f(m.group(1))
if p99 is None:
    m = re.search(r'\b(?:p99|99th)\b.*?([\d.]+)', txt, re.I)
    if m: p99 = f(m.group(1))

# If we found avg but units might be "usec" already.
# We'll assume values are microseconds (sockperf typically reports usec).
vals = [min_v, avg_v, p50, p99, max_v]
ok = all(v is not None for v in [min_v, avg_v, max_v])

if not ok:
    print(",,,,,,1")
    sys.exit(0)

def fmt(x):
    return "" if x is None else f"{x:.3f}"

print(f"{fmt(min_v)},{fmt(avg_v)},{fmt(p50)},{fmt(p99)},{fmt(max_v)},0")
PY
}

run_sockperf_pingpong_once() {
  # prints CSV row fields: min_us,avg_us,p50_us,p99_us,max_us,timeout
  local host_ip="$1" peer_ip="$2" size="$3" raw_out="$4"
  local tmp="${raw_out}.tmp"

  # sockperf client (sender)
  # -i peer, -p port, --full-rtt, -m msg size, -t test time, --src-port keep tc matching stable
  # Some sockperf builds use "--src-port" and some use "--sender-port".
  # We'll try --src-port first, fall back to --sender-port if needed.
  {
    echo "sockperf ping-pong --full-rtt -i ${peer_ip} -p ${PORT} -m ${size} -t ${SOCKPERF_TIME_SEC} --src-port ${PORT}"
    echo "host_ip=${host_ip} peer_ip=${peer_ip} port=${PORT} msg_size=${size} time_sec=${SOCKPERF_TIME_SEC}"
    echo "-----"
  } > "$raw_out"

  if sockperf ping-pong --full-rtt -i "$peer_ip" -p "$PORT" -m "$size" -t "$SOCKPERF_TIME_SEC" --src-port "$PORT" >>"$raw_out" 2>&1; then
    :
  else
    # fallback flag name
    if sockperf ping-pong --full-rtt -i "$peer_ip" -p "$PORT" -m "$size" -t "$SOCKPERF_TIME_SEC" --sender-port "$PORT" >>"$raw_out" 2>&1; then
      :
    else
      echo ",,,,,,1"
      return 0
    fi
  fi

  local parsed
  parsed="$(parse_sockperf_to_csv "$raw_out" || true)"
  [[ -n "${parsed:-}" ]] || parsed=",,,,,,1"
  echo "$parsed"
}

run_rtt_server_mode() {
  local label="$1" host_ip="$2" stamp="$3"
  local outdir="results/${label}/${IFACE}/rtt/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=server"
    echo "test=rtt"
    echo "tool=sockperf"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "sockperf server (sr)"
  } > "${outdir}/meta_server.txt"

  local logfile="${outdir}/sockperf_server.log"

  echo
  echo "== SERVER MODE (RTT / sockperf sr) =="
  echo "Run folder: $outdir"
  echo "Logging server output to: $logfile"
  echo "Listening on: ${host_ip}:${PORT}"
  echo "Stop with Ctrl+C after sender finishes."
  echo

  # Run sockperf server bound to host_ip
  # Some versions use "-i" to bind. We keep it explicit.
  sockperf sr -i "$host_ip" -p "$PORT" 2>&1 | tee "$logfile"
}

run_rtt_sender_mode() {
  local label="$1" host_ip="$2" peer_ip="$3" stamp="$4" runs_default="$5" runs_override="$6"
  local outdir="results/${label}/${IFACE}/rtt/${stamp}"
  mkdir -p "$outdir"

  {
    echo "role=sender"
    echo "test=rtt"
    echo "tool=sockperf"
    echo "auth=${label}"
    echo "iface=${IFACE}"
    echo "host_ip=${host_ip}"
    echo "peer_ip=${peer_ip}"
    echo "port=${PORT}"
    echo "timestamp=${stamp}"
    echo
    echo "sockperf ping-pong --full-rtt"
    echo "runs_default=${runs_default}"
    echo "runs_override_for_32_1024_8192=${runs_override}"
    echo "sizes=${SIZES[*]}"
    echo "time_per_run_sec=${SOCKPERF_TIME_SEC}"
  } > "${outdir}/meta_sender.txt"

  local csv="${outdir}/results.csv"
  : > "$csv"
  echo "timestamp,run_index,msg_size_bytes,tool,time_sec,rtt_min_us,rtt_avg_us,rtt_p50_us,rtt_p99_us,rtt_max_us,timeout" >> "$csv"

  echo
  echo "== SENDER MODE (RTT / sockperf ping-pong --full-rtt) =="
  echo "Run folder: $outdir"
  echo "Target: ${peer_ip}:${PORT}"
  echo "Time per run: ${SOCKPERF_TIME_SEC}s"
  echo "Default runs per size: ${runs_default}"
  if [[ "$runs_override" -gt 0 ]]; then
    echo "Override runs for sizes {32,1024,8192}: ${runs_override}"
  fi
  echo

  for sz in "${SIZES[@]}"; do
    local runs_for_size="$runs_default"
    if [[ "$runs_override" -gt 0 ]]; then
      if [[ "$sz" == "32" || "$sz" == "1024" || "$sz" == "8192" ]]; then
        runs_for_size="$runs_override"
      fi
    fi

    echo "=== Size ${sz} bytes: ${runs_for_size} runs (each ${SOCKPERF_TIME_SEC}s) ==="

    for run in $(seq 1 "$runs_for_size"); do
      local logdir="${outdir}/run_${run}/sz_${sz}"
      mkdir -p "$logdir"
      local raw="${logdir}/rtt_raw.txt"
      local ts; ts="$(date +%s)"

      local parsed
      parsed="$(run_sockperf_pingpong_once "$host_ip" "$peer_ip" "$sz" "$raw" || true)"
      [[ -n "${parsed:-}" ]] || parsed=",,,,,,1"

      # parsed is: min,avg,p50,p99,max,timeout
      echo "${ts},${run},${sz},sockperf,${SOCKPERF_TIME_SEC},${parsed}" >> "$csv"
    done
  done

  echo
  echo "Done."
  echo "CSV: $csv"
  echo "Raw logs: $outdir/run_*/sz_*/rtt_raw.txt"
}
# --------------------------------------------------------------------------

kill_all_iperf3() {
  echo "[prep] Killing any running iperf3 / sockperf and freeing port $PORT (best effort)..."

  sudo pkill -9 iperf3 2>/dev/null || true
  sudo pkill -9 sockperf 2>/dev/null || true

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
  local role label stamp runs runs_override host_ip peer_ip

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
  runs_override=0
  if [[ "$role" == "sender" ]]; then
    if [[ "$TEST_KIND" == "bandwidth" ]]; then
      runs="$(ask_int "How many runs per msg_size?" "32")"
    else
      runs="$(ask_int "How many RTT runs per msg_size (default for all sizes)?" "32")"
      runs_override="$(ask_int_allow_zero "Override runs for sizes {32,1024,8192}? (0 = no override)" "0")"
    fi
  fi

  need_iperf3_if_bandwidth
  need_sockperf_if_rtt

  kill_all_iperf3

  if [[ "$label" == "auth_on" ]]; then
    auth_start_on_this_node "$host_ip"
  else
    auth_clean_only
  fi

  if [[ "$TEST_KIND" == "bandwidth" ]]; then
    if [[ "$role" == "server" ]]; then
      run_server_mode "$label" "$host_ip" "$stamp"
    else
      run_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs"
    fi
    exit 0
  fi

  # RTT mode (sockperf)
  if [[ "$role" == "server" ]]; then
    run_rtt_server_mode "$label" "$host_ip" "$stamp"
  else
    run_rtt_sender_mode "$label" "$host_ip" "$peer_ip" "$stamp" "$runs" "$runs_override"
  fi
}

main "$@"
