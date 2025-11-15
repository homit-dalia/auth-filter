#!/usr/bin/env bash
# run_sockperf_max.sh — UDP throughput sweep using sockperf (max rate)
set -u

# ------- config -------
SERVER_IP="192.168.100.1"
CLIENT_IFACE="enp175s0f0np0"
CLIENT_BIND_IP="192.168.100.2"
DURATION_SEC=10
SIZES=(128 256 512 1024 2048 4096 8192 16384 32768 65507)
# ----------------------

command -v sockperf >/dev/null || { echo "sockperf not found"; exit 1; }
command -v python3  >/dev/null || { echo "python3 not found"; exit 1; }

# sanity check
if ! ip -4 -o addr show dev "${CLIENT_IFACE}" | grep -q "${CLIENT_BIND_IP}/"; then
  echo "WARNING: ${CLIENT_BIND_IP} not configured on ${CLIENT_IFACE}; sockperf binds may fail."
fi

read -r -p "Is auth enabled? [y/N]: " ans
case "$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]')" in
  y|yes) LABEL="auth_on" ;;
  *)     LABEL="auth_off" ;;
esac

BASE_OUTDIR="results/${LABEL}/${CLIENT_IFACE}/sockperf_max"
mkdir -p "${BASE_OUTDIR}"

CSV="${BASE_OUTDIR}/sockperf_max.csv"
: > "${CSV}"
echo "timestamp,bandwidth_target,msg_size_bytes,bitrate_bps,loss_percent,packets,lost_packets,jitter_ms" >> "${CSV}"

echo "=== Sockperf max throughput ==="

for sz in "${SIZES[@]}"; do
  echo "--- msg_size=${sz} ---"
  OUTDIR="${BASE_OUTDIR}/sz_${sz}"
  LOGDIR="${OUTDIR}/logs"
  mkdir -p "${OUTDIR}" "${LOGDIR}"

  RAW_OUT="${LOGDIR}/sockperf_sz${sz}.txt"
  ERR_TMP="${LOGDIR}/sockperf_sz${sz}.err"

  # Run sockperf, raw output
  if ! sockperf throughput \
         --client_ip "${CLIENT_BIND_IP}" \
         -i "${SERVER_IP}" \
         -p 11111 \
         --msg-size "${sz}" \
         --time "${DURATION_SEC}" \
         --full-rtt \
         > "${RAW_OUT}" 2> "${ERR_TMP}"; then
    echo "WARN: sockperf failed for size=${sz}; see ${ERR_TMP}"
  fi

  python3 - "${RAW_OUT}" "${sz}" >> "${CSV}" <<'PY'
import sys, time, re

raw_path = sys.argv[1]
msz = sys.argv[2]
ts = int(time.time())

try:
    txt = open(raw_path).read()
except:
    print(f"{ts},max,{msz},,,,,")
    sys.exit(0)

# Defaults if parsing fails
mbps = ""
pkts = ""
lost = ""
loss_pct = ""
jitter = ""

# Extract BandWidth Mbps
m = re.search(r'BandWidth .*?\(([\d.]+)\s*Mbps\)', txt)
if m:
    mbps = float(m.group(1)) * 1e6  # convert Mbps → bps

# Extract messages sent
m = re.search(r'Total of (\d+)\s+messages sent', txt)
if m:
    pkts = m.group(1)

# Extract message rate (msg/sec) — optional but not directly used
# Extract dropped packets (rare in sockperf throughput)
m = re.search(r'dropped.*?(\d+)', txt)
if m:
    lost = m.group(1)

# Generate loss percent if both present
try:
    if pkts and lost:
        loss_pct = 100 * (int(lost) / int(pkts))
except:
    loss_pct = ""

print(f"{ts},max,{msz},{mbps},{loss_pct},{pkts},{lost},{jitter}")
PY

done

echo
echo "Done."
echo "CSV: ${CSV}"
echo "Raw logs: ${BASE_OUTDIR}/sz_*/logs/"