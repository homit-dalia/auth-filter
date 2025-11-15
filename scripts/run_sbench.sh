#!/usr/bin/env bash
# run_sockperf_max.sh — UDP throughput sweep using sockperf (max rate)
set -u

# ------- config -------
SERVER_IP="192.168.100.1"
CLIENT_IFACE="enp175s0f0np0"
CLIENT_BIND_IP="192.168.100.2"
DURATION_SEC=10
SIZES=(128 256 512 1024 2048 4096 8192 16384 32768 65536)
# ----------------------

command -v sockperf >/dev/null || { echo "sockperf not found"; exit 1; }
command -v python3  >/dev/null || { echo "python3 not found"; exit 1; }

# sanity check: interface has that IP
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

  JSON_TMP="${LOGDIR}/sockperf_sz${sz}.json"
  ERR_TMP="${LOGDIR}/sockperf_sz${sz}.err"

  # Max-rate test (no --pps)
  if ! sockperf throughput \
         --client_ip "${CLIENT_BIND_IP}" \
         -i "${SERVER_IP}" \
         --msg-size "${sz}" \
         --time "${DURATION_SEC}" \
         --full-rtt \
         --json \
         > "${JSON_TMP}" 2> "${ERR_TMP}"; then
    echo "WARN: sockperf failed for size=${sz}; see ${ERR_TMP}"
  fi

  python3 - "${JSON_TMP}" "${sz}" >> "${CSV}" <<'PY'
import json, sys, time
jpath, msz = sys.argv[1], sys.argv[2]
ts = int(time.time())
try:
    with open(jpath) as f:
        data = json.load(f)
except:
    print(f"{ts},max,{msz},,,,,")
    sys.exit(0)

s = data.get("sockperf", {})
r = s.get("throughput", {})

bps    = r.get("bytes-per-sec", 0) * 8 if r.get("bytes-per-sec") else ""
loss   = r.get("packet-loss-percent", "")
pkts   = r.get("sent-msg", "")
lost   = r.get("dropped-msg", "")
jitter = r.get("jitter-usec", "")

if isinstance(jitter, (int,float)):
    jitter = jitter / 1000.0

print(f"{ts},max,{msz},{bps},{loss},{pkts},{lost},{jitter}")
PY

done

echo
echo "Done."
echo "CSV: ${CSV}"
echo "Raw logs: ${BASE_OUTDIR}/sz_*/logs/"