#!/usr/bin/env python3
import socket, struct

# Fallbacks for systems/Python builds missing these names
IP_RECVTTL  = getattr(socket, "IP_RECVTTL", 12)     # enable TTL cmsg
IP_RECVTOS  = getattr(socket, "IP_RECVTOS", 13)     # enable TOS cmsg
IP_PKTINFO  = getattr(socket, "IP_PKTINFO", 8)      # enable pktinfo cmsg
IP_TTL      = getattr(socket, "IP_TTL", 2)          # cmsg type you receive
IP_TOS      = getattr(socket, "IP_TOS", 1)          # cmsg type you receive

BIND_IP = "192.168.200.1"
PORT    = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, IP_RECVTOS, 1)
s.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
s.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
s.bind((BIND_IP, PORT))

print(f"listening on {BIND_IP}:{PORT} ...")

while True:
    data, anc, flags, addr = s.recvmsg(4096, 1024)
    tos = ttl = None
    iif = None

    for level, ctype, cdata in anc:
        if level == socket.IPPROTO_IP and ctype == IP_TOS:
            tos = cdata[0]
        elif level == socket.IPPROTO_IP and ctype == IP_TTL:
            ttl = cdata[0]
        elif level == socket.IPPROTO_IP and ctype == IP_PKTINFO:
            # struct in_pktinfo { unsigned int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; }
            ifindex = int.from_bytes(cdata[:4], "little")
            try:
                iif = socket.if_indextoname(ifindex)
            except OSError:
                iif = str(ifindex)

    dscp = (tos or 0) >> 2
    reinjected = (iif == "auth0") and (dscp == 46) and (ttl == 63)  # DSCP EF = 46

    print(f"from {addr} len={len(data)} iif={iif} TOS=0x{(tos or 0):02x} DSCP={dscp} TTL={ttl} reinjected={reinjected}")