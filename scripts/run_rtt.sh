#!/usr/bin/env bash
# run_rtt.sh — RTT sweep (sockperf ping-pong) from bodhi
set -u  # (not -e so we can keep going if one test fails)

# ------- config -------
SERVER_IP="192.168.200.1"  # banyan
SOCKPERF_PORT=9999         # IMPORTANT: use a port the reinjector actually processes
DURATION_SEC=10
SIZES=(128 256 512 1024 1500 2048 4096 8192)
# ----------------------

command -v sockperf >/dev/null || { echo "sockperf not found"; exit 1; }

read -r -p "Is auth enabled? [y/N]: " ans
case "$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]')" in
  y|yes) LABEL="auth_on" ;;
  *)     LABEL="auth_off" ;;
esac

OUTDIR="results/${LABEL}"
LOGDIR="${OUTDIR}/logs"
mkdir -p "${OUTDIR}" "${LOGDIR}"

RTT_CSV="${OUTDIR}/sockperf_rtt.csv"
: > "${RTT_CSV}"  # overwrite
echo "timestamp,msg_size_bytes,avg_usec,stddev_usec,min_usec,max_usec" >> "${RTT_CSV}"

echo "=== RTT (sockperf ping-pong) ==="
for sz in "${SIZES[@]}"; do
  echo "Running sockperf size=${sz}..."
  OUT_TMP="${LOGDIR}/sockperf_${sz}.txt"
  if ! sockperf ping-pong -i "${SERVER_IP}" -p "${SOCKPERF_PORT}" -m "${sz}" -t "${DURATION_SEC}" \
        > "${OUT_TMP}" 2>&1; then
    echo "WARN: sockperf failed for size=${sz}; see ${OUT_TMP}"
  fi
  ts=$(date +%s)
  # same fields/units as before (usec)
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