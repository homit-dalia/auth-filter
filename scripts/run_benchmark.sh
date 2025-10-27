#!/usr/bin/env bash
# run_bandwidth.sh — UDP bandwidth sweep (iperf3) from bodhi
set -u  # (not -e so we can keep going if one test fails)

# ------- config -------
SERVER_IP="192.168.200.1"      # banyan
CLIENT_IFACE="eno1"            # interface on bodhi that has CLIENT_BIND_IP
CLIENT_BIND_IP="192.168.200.2" # must exist on CLIENT_IFACE
IPERF_PORT=9999                # make sure iperf3 -s on banyan uses this
DURATION_SEC=10
TARGET_BW="100000M"
SIZES=(128 256 512 1024 1500 2048 4096 8192)
# ----------------------

command -v iperf3 >/dev/null || { echo "iperf3 not found"; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }

# quick sanity: is the bind IP present?
if ! ip -4 -o addr show dev "${CLIENT_IFACE}" | grep -q "${CLIENT_BIND_IP}/"; then
  echo "WARNING: ${CLIENT_BIND_IP} not configured on ${CLIENT_IFACE}; iperf3 binds may fail."
fi

read -r -p "Is auth enabled? [y/N]: " ans
case "$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]')" in
  y|yes) LABEL="auth_on" ;;
  *)     LABEL="auth_off" ;;
esac

OUTDIR="results/${LABEL}"
LOGDIR="${OUTDIR}/logs"
mkdir -p "${OUTDIR}" "${LOGDIR}"

IPERF_CSV="${OUTDIR}/iperf_bandwidth.csv"
: > "${IPERF_CSV}"  # overwrite
echo "timestamp,msg_size_bytes,bitrate_bps,loss_percent,packets,lost_packets,jitter_ms" >> "${IPERF_CSV}"

echo "=== Bandwidth (iperf3) ==="
for sz in "${SIZES[@]}"; do
  echo "Running iperf3 size=${sz}..."
  JSON_TMP="${LOGDIR}/iperf_${sz}.json"
  ERR_TMP="${LOGDIR}/iperf_${sz}.err"

  if ! iperf3 -c "${SERVER_IP}" -u -p "${IPERF_PORT}" -B "${CLIENT_BIND_IP}" \
              -l "${sz}" -b "${TARGET_BW}" -t "${DURATION_SEC}" -J \
              > "${JSON_TMP}" 2> "${ERR_TMP}"; then
    echo "WARN: iperf3 failed for size=${sz}; see ${ERR_TMP}"
  fi

  # Parse iperf3 JSON to our CSV schema (same columns as before)
  python3 - "${JSON_TMP}" "${sz}" >> "${IPERF_CSV}" <<'PY'
import json, sys, time
jpath, msz = sys.argv[1], sys.argv[2]
ts = int(time.time())
try:
    with open(jpath,'r') as f: data = json.load(f)
except Exception:
    print(f"{ts},{msz},,,,,")
    sys.exit(0)
end = data.get('end', {})
summary = None
for k in ('sum_received','sum','sum_sent'):
    if isinstance(end.get(k), dict):
        summary = end[k]; break
if not summary:
    print(f"{ts},{msz},,,,,"); sys.exit(0)
bps     = summary.get('bits_per_second','')
losspct = summary.get('lost_percent','')
pkts    = summary.get('packets','')
lost    = summary.get('lost_packets','')
jitter  = summary.get('jitter_ms','')
print(f"{ts},{msz},{bps},{losspct},{pkts},{lost},{jitter}")
PY
done

echo
echo "Done."
echo "Bandwidth CSV: ${IPERF_CSV}"
echo "Raw logs:      ${LOGDIR}/"