# udp_sender.py
import argparse, socket, time, struct, signal, sys, os

# --- Defaults for Bodhi -> Banyan over eno1 ---
DEST_IP      = "192.168.200.1"   # banyan
DEST_PORT    = 9999
SRC_IP       = "192.168.200.2"   # bodhi eno1
BIND_DEVICE  = "eno1"            # best-effort (requires root); falls back to SRC_IP bind
INTERVAL_S   = 1.0               # 1 pkt/sec
PAYLOAD_SIZE = 64                # bytes (>=16 enforced)
COUNT        = 0                 # 0 = infinite
# ---------------------------------------------

stats = {"sent": 0, "start_ns": 0}

def on_exit(*_):
    dur_s = max(1e-9 * (time.monotonic_ns() - stats["start_ns"]), 1e-9)
    rate = stats["sent"] / dur_s
    print(f"\nSent {stats['sent']} packets in {dur_s:.3f}s ({rate:.3f} pkt/s)")
    sys.exit(0)

def maybe_bind_device(sock, devname):
    """
    Try to pin the socket to a specific interface (Linux-only, root required).
    If it fails (not root / unsupported), we silently continue.
    """
    try:
        SO_BINDTODEVICE = 25  # not in Python's socket module
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, devname.encode() + b"\x00")
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="Send UDP packets at 1 pkt/s (Bodhi->Banyan default).")
    parser.add_argument("dest", nargs="?", default=DEST_IP, help="Destination IP/host (default 192.168.200.1)")
    parser.add_argument("port", nargs="?", type=int, default=DEST_PORT, help="Destination UDP port (default 9999)")
    parser.add_argument("--size", type=int, default=PAYLOAD_SIZE, help="Payload size bytes (default 64)")
    parser.add_argument("--count", type=int, default=COUNT, help="Packets to send (0=infinite)")
    parser.add_argument("--interval", type=float, default=INTERVAL_S, help="Seconds between packets (default 1.0)")
    parser.add_argument("--src-ip", default=SRC_IP, help="Bind source IP (default 192.168.200.2)")
    parser.add_argument("--device", default=BIND_DEVICE, help="Bind to interface (best-effort, default eno1)")
    parser.add_argument("--ttl", type=int, help="IP TTL (1-255)")
    parser.add_argument("--tos", type=int, help="IP TOS/DSCP byte (0-255)")
    args = parser.parse_args()

    # Prepare socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Best-effort pin to interface first (requires root), else bind by source IP
    pinned = False
    if args.device:
        pinned = maybe_bind_device(s, args.device)
    if not pinned and args.src_ip:
        s.bind((args.src_ip, 0))

    if args.ttl is not None:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, args.ttl)
    if args.tos is not None:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.tos)

    # Resolve destination once
    dest_addr = (socket.gethostbyname(args.dest), args.port)

    # Ensure payload big enough for our header (seq + t_ns = 16 bytes)
    min_hdr = 16
    payload_size = max(args.size, min_hdr)

    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)
    stats["start_ns"] = time.monotonic_ns()

    seq = 0
    next_send = time.monotonic()
    print(
        f"Sending to {dest_addr[0]}:{dest_addr[1]} every {args.interval:.3f}s, "
        f"size={payload_size}B, {'infinite' if args.count==0 else args.count} packets.\n"
        f"Source: {args.src_ip or 'auto'} "
        f"{'(pinned to ' + args.device + ')' if pinned else '(device pin failed or not used; bound by src IP)'}.\n"
        "Press Ctrl+C to stop."
    )

    while True:
        # Build payload: 8B sequence, 8B send timestamp (ns), then padding
        t_ns = time.monotonic_ns()
        header = struct.pack("!QQ", seq, t_ns)
        buf = header + bytes(payload_size - len(header))

        s.sendto(buf, dest_addr)
        seq += 1
        stats["sent"] = seq

        if args.count and seq >= args.count:
            break

        # Sleep with low drift
        print(f"Sent packet seq={seq-1} time={t_ns} ns", end="\r")
        next_send += args.interval
        delay = next_send - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            # If we fell behind (hiccup), reset schedule to avoid drift
            next_send = time.monotonic()

    on_exit()

if __name__ == "__main__":
    main()