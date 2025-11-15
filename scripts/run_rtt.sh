#!/usr/bin/env bash
# run_rtt.sh — RTT sweep (sockperf ping-pong) from bodhi
set -u  # (not -e so we can keep going if one test fails)

# ------- config -------
SERVER_IP="192.168.100.1"   # banyan
SOCKPERF_PORT=9999          # IMPORTANT: reinjector should process this
CLIENT_IFACE="enp175s0f0np0"  # for labeling/sanity checks
DURATION_SEC=10
# sizes up to 65536
SIZES=(128 256 512 1024 2048 4096 8192 16384 32768 65507)
# ----------------------

command -v sockperf >/dev/null || { echo "sockperf not found"; exit 1; }

# (Optional) interface presence sanity
ip link show "${CLIENT_IFACE}" >/dev/null 2>&1 || \
  echo "WARNING: ${CLIENT_IFACE} not found (continuing)."

read -r -p "Is auth enabled? [y/N]: " ans
case "$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]')" in
  y|yes) LABEL="auth_on" ;;
  *)     LABEL="auth_off" ;;
esac

OUTDIR="results/${LABEL}/${CLIENT_IFACE}/rtt"
LOGDIR="${OUTDIR}/logs"
mkdir -p "${OUTDIR}" "${LOGDIR}"

RTT_CSV="${OUTDIR}/sockperf_rtt.csv"
: > "${RTT_CSV}"  # overwrite
echo "timestamp,msg_size_bytes,avg_usec,stddev_usec,min_usec,max_usec" >> "${RTT_CSV}"

echo "=== RTT (sockperf ping-pong) ==="
for sz in "${SIZES[@]}"; do
  echo "Running sockperf size=${sz} for ${DURATION_SEC}s..."
  OUT_TMP="${LOGDIR}/sockperf_${sz}.txt"
  if ! sockperf ping-pong -i "${SERVER_IP}" -p "${SOCKPERF_PORT}" -m "${sz}" -t "${DURATION_SEC}" \
        > "${OUT_TMP}" 2>&1; then
    echo "WARN: sockperf failed for size=${sz}; see ${OUT_TMP}"
  fi
  ts=$(date +%s)
  avg=$(awk 'match($0,/avg-latency=([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
  std=$(awk 'match($0,/std-dev=([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
  min=$(awk 'match($0,/<MIN> observation = *([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
  max=$(awk 'match($0,/<MAX> observation = *([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
  echo "${ts},${sz},${avg},${std},${min},${max}" >> "${RTT_CSV}"
done

echo
echo "Done."
echo "RTT CSV:  ${RTT_CSV}"
echo "Raw logs: ${LOGDIR}/"