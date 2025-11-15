#!/usr/bin/env bash
# run_bandwidth.sh — UDP bandwidth sweep (iperf3) from bodhi
set -u  # (not -e so we can keep going if one test fails)

# ------- config -------
SERVER_IP="192.168.100.1"        # banyan
CLIENT_IFACE="enp175s0f0np0"     # interface on bodhi
CLIENT_BIND_IP="192.168.100.2"   # must exist on CLIENT_IFACE
IPERF_PORT=9999                  # iperf3 -s on banyan should use this
DURATION_SEC=10
BANDWIDTHS=("1G" "10G" "25G" "50G" "100G")
# sizes up to 65536
SIZES=(128 256 512 1024 2048 4096 8192 16384 32768 65536)
# ----------------------

command -v iperf3 >/dev/null || { echo "iperf3 not found"; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }

# sanity: is the bind IP present on the chosen iface?
if ! ip -4 -o addr show dev "${CLIENT_IFACE}" | grep -q "${CLIENT_BIND_IP}/"; then
  echo "WARNING: ${CLIENT_BIND_IP} not configured on ${CLIENT_IFACE}; iperf3 binds may fail."
fi

read -r -p "Is auth enabled? [y/N]: " ans
case "$(echo "${ans:-n}" | tr '[:upper:]' '[:lower:]')" in
  y|yes) LABEL="auth_on" ;;
  *)     LABEL="auth_off" ;;
esac

BASE_OUTDIR="results/${LABEL}/${CLIENT_IFACE}/iperf"
mkdir -p "${BASE_OUTDIR}"

# Top-level CSV for all bandwidths/sizes
IPERF_CSV="${BASE_OUTDIR}/iperf_bandwidth.csv"
: > "${IPERF_CSV}"  # overwrite
echo "timestamp,bandwidth_target,msg_size_bytes,bitrate_bps,loss_percent,packets,lost_packets,jitter_ms" >> "${IPERF_CSV}"

echo "=== Bandwidth (iperf3 UDP) ==="
for bw in "${BANDWIDTHS[@]}"; do
  echo "--- Target bandwidth: ${bw} ---"
  OUTDIR="${BASE_OUTDIR}/bw_${bw}"
  LOGDIR="${OUTDIR}/logs"
  mkdir -p "${OUTDIR}" "${LOGDIR}"

  for sz in "${SIZES[@]}"; do
    echo "Running iperf3 size=${sz}, bw=${bw}, duration=${DURATION_SEC}s..."
    JSON_TMP="${LOGDIR}/iperf_sz${sz}.json"
    ERR_TMP="${LOGDIR}/iperf_sz${sz}.err"

    if ! iperf3 -c "${SERVER_IP}" -u -p "${IPERF_PORT}" -B "${CLIENT_BIND_IP}" \
                -l "${sz}" -b "${bw}" -t "${DURATION_SEC}" -J \
                > "${JSON_TMP}" 2> "${ERR_TMP}"; then
      echo "WARN: iperf3 failed for size=${sz}, bw=${bw}; see ${ERR_TMP}"
    fi

    # Parse iperf3 JSON to our CSV schema
    python3 - "${JSON_TMP}" "${sz}" "${bw}" >> "${IPERF_CSV}" <<'PY'
import json, sys, time
jpath, msz, bwlab = sys.argv[1], sys.argv[2], sys.argv[3]
ts = int(time.time())
try:
    with open(jpath,'r') as f: data = json.load(f)
except Exception:
    print(f"{ts},{bwlab},{msz},,,,,")
    sys.exit(0)
end = data.get('end', {})
summary = None
for k in ('sum_received','sum','sum_sent'):
    if isinstance(end.get(k), dict):
        summary = end[k]; break
if not summary:
    print(f"{ts},{bwlab},{msz},,,,,"); sys.exit(0)
bps     = summary.get('bits_per_second','')
losspct = summary.get('lost_percent','')
pkts    = summary.get('packets','')
lost    = summary.get('lost_packets','')
jitter  = summary.get('jitter_ms','')
print(f"{ts},{bwlab},{msz},{bps},{losspct},{pkts},{lost},{jitter}")
PY

  done
done

echo
echo "Done."
echo "Bandwidth CSV: ${IPERF_CSV}"
echo "Raw logs:      ${BASE_OUTDIR}/bw_*/logs/"