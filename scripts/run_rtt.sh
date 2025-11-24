#!/usr/bin/env bash
# run_rtt.sh — RTT sweep (sockperf ping-pong) from bodhi, multi-run
set -u  # (not -e so we can keep going if one test fails)

# ------- config -------
SERVER_IP="192.168.100.1"      # banyan
SOCKPERF_PORT=9999             # IMPORTANT: reinjector should process this
CLIENT_IFACE="enp175s0f0np0"   # for labeling/sanity checks
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

# how many runs per size?
read -r -p "How many runs per msg_size? " RUNS
if ! [[ "${RUNS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: RUNS must be a positive integer, got '${RUNS}'"
  exit 1
fi

BASE_ROOT="results/${LABEL}/${CLIENT_IFACE}/rtt"
mkdir -p "${BASE_ROOT}"

RTT_CSV="${BASE_ROOT}/sockperf_rtt_all_runs.csv"
: > "${RTT_CSV}"
echo "timestamp,run_index,msg_size_bytes,avg_usec,stddev_usec,min_usec,max_usec" >> "${RTT_CSV}"

echo "=== RTT (sockperf ping-pong, multi-run) ==="
echo "Label=${LABEL}, iface=${CLIENT_IFACE}, runs=${RUNS}"

for run in $(seq 1 "${RUNS}"); do
  echo
  echo "=== Run ${run}/${RUNS} ==="
  RUN_OUTDIR="${BASE_ROOT}/run_${run}"
  LOGDIR="${RUN_OUTDIR}/logs"
  mkdir -p "${RUN_OUTDIR}" "${LOGDIR}"

  for sz in "${SIZES[@]}"; do
    echo "Running sockperf run=${run}, size=${sz} for ${DURATION_SEC}s..."
    OUT_TMP="${LOGDIR}/sockperf_${sz}.txt"

    if ! sockperf ping-pong -i "${SERVER_IP}" -p "${SOCKPERF_PORT}" -m "${sz}" -t "${DURATION_SEC}" \
          > "${OUT_TMP}" 2>&1; then
      echo "WARN: sockperf failed (run=${run}, size=${sz}); see ${OUT_TMP}"
    fi

    ts=$(date +%s)
    avg=$(awk 'match($0,/avg-latency=([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
    std=$(awk 'match($0,/std-dev=([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
    min=$(awk 'match($0,/<MIN> observation = *([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)
    max=$(awk 'match($0,/<MAX> observation = *([0-9.]+)/,a){print a[1]}' "${OUT_TMP}" | tail -n1)

    echo "${ts},${run},${sz},${avg},${std},${min},${max}" >> "${RTT_CSV}"
  done
done

echo
echo "Done."
echo "RTT CSV (all runs):  ${RTT_CSV}"
echo "Raw logs per run/size: ${BASE_ROOT}/run_*/logs/"