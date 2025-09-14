# auth-filter

egress filtering for authentication packets

hd431@bodhi:~/auth-filter$ # Remove the broad rule that’s matching everything
sudo tc filter del dev eno1 egress pref 100 handle 0x1 flower

# (Reassert the intended DSCP-masked mirror+drop, idempotent)
sudo tc filter replace dev eno1 egress pref 100 protocol ip \
  flower skip_hw ip_proto udp src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# Verify only one rule remains and counters grow on it
sudo tc -s filter show dev eno1 egress
RTNETLINK answers: File exists
We have an error talking to the kernel
filter protocol ip pref 100 flower chain 0 
filter protocol ip pref 100 flower chain 0 handle 0x2 
  eth_type ipv4
  ip_proto udp
  ip_tos 0/0xfc
  dst_ip 192.168.200.1
  src_ip 192.168.200.2
  dst_port 9999
  skip_hw
  not_in_hw
        action order 1: mirred (Egress Mirror to device ifb0) pipe
        index 1 ref 1 bind 1 installed 258 sec used 258 sec
        Action statistics:
        Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
        backlog 0b 0p requeues 0

        action order 2: gact action drop
         random type none pass val 0
         index 1 ref 1 bind 1 installed 258 sec used 258 sec
        Action statistics:
        Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
        backlog 0b 0p requeues 0

hd431@bodhi:~/auth-filter$ 












# banyan

# mirror+drop originals on ingress so only verified copies get delivered
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true
sudo tc filter replace dev eno1 ingress pref 100 protocol ip \
  flower ip_proto udp src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  action mirred egress mirror dev ifb0 \
  action drop

# create the TUN that will feed the host stack
sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
# helps when dst IP equals a local address on a different iface
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1

# 1) Keep this (you set it earlier): allow “local” dst on this iface
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1

# 2) Disable reverse path filtering so TUN-injected packets aren’t dropped
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0













net.ipv4.conf.auth0.accept_local=1
net.ipv4.conf.auth0.rp_filter=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0



Bodhi

# 0) Stop the reinjector (source mode), if running
sudo pkill -f 'af_reinject.*--mode source' 2>/dev/null || true

# 1) Remove the egress flower rule(s) on eno1
sudo tc filter del dev eno1 egress pref 100 2>/dev/null || true

# 2) (Optional) remove the clsact qdisc entirely on eno1
#    (this wipes any ingress/egress filters attached to clsact)
sudo tc qdisc del dev eno1 clsact 2>/dev/null || true

# 3) (Optional) delete the IFB used for mirroring
sudo ip link del ifb0 2>/dev/null || true

# 4) Verify nothing remains
sudo tc -s filter show dev eno1 egress || true
ip link show ifb0 || echo "ifb0 removed"











# IFB + clsact
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# INGRESS rule: mirror from banyan src 192.168.200.1:9999 to bodhi, then DROP wire copy
sudo tc filter replace dev eno1 ingress pref 200 protocol ip \
  flower ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  action mirred egress mirror dev ifb0 \
  action drop

# TUN for verified delivery into INPUT
ip link show auth0 >/dev/null 2>&1 || sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0

# Run verifier on bodhi (dest mode)
sudo ./af_reinject --mode dest





Banyan

# 0) Stop the reinjector (dest mode), if running
sudo pkill -f 'af_reinject.*--mode dest' 2>/dev/null || true

# 1) Remove the ingress mirror+drop rule(s) on eno1
sudo tc filter del dev eno1 ingress pref 100 2>/dev/null || true

# 2) (Optional) remove the clsact qdisc on eno1
sudo tc qdisc del dev eno1 clsact 2>/dev/null || true

# 3) (Optional) revert TUN-related sysctls (do this BEFORE deleting auth0)
#    If you set these earlier, flip them back; harmless if not present.
sudo sysctl -w net.ipv4.conf.auth0.accept_local=0 2>/dev/null || true
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=1 2>/dev/null || true   # or 2 (loose), if that's your site default

# 4) Delete the TUN and IFB devices
sudo ip link del auth0 2>/dev/null || true
sudo ip link del ifb0 2>/dev/null || true

# 5) (Optional) if you created a temporary nftables allow chain, remove it
sudo nft delete table inet auth_allow 2>/dev/null || true

# 6) Verify cleanup
sudo tc -s filter show dev eno1 ingress || true
ip link show auth0 || echo "auth0 removed"
ip link show ifb0   || echo "ifb0 removed"



# IFB + clsact (reuse if already present)
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# EGRESS rule: mirror ONLY originals (DSCP=0) from 192.168.200.1:9999 → 192.168.200.2, then DROP them
sudo tc filter replace dev eno1 egress pref 200 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# Run signer on banyan (source mode)
sudo ./af_reinject --mode source









# Bodhi full

# IFB + clsact
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# EGRESS (bodhi→banyan): mirror originals (DSCP=0) then DROP
sudo tc filter replace dev eno1 egress pref 100 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# INGRESS (banyan→bodhi replies): mirror then DROP wire copy
sudo tc filter replace dev eno1 ingress pref 200 protocol ip \
  flower ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  action mirred egress mirror dev ifb0 \
  action drop

# TUN for verified delivery into INPUT
ip link show auth0 >/dev/null 2>&1 || sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0


# Banyan full

# IFB + clsact
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# INGRESS (bodhi→banyan): mirror then DROP wire copy
sudo tc filter replace dev eno1 ingress pref 100 protocol ip \
  flower ip_proto udp \
  src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  action mirred egress mirror dev ifb0 \
  action drop

# EGRESS (banyan→bodhi replies): mirror originals (DSCP=0) then DROP
sudo tc filter replace dev eno1 egress pref 200 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# TUN for verified delivery into INPUT
ip link show auth0 >/dev/null 2>&1 || sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0







## RESET

# --- Run on BOTH hosts (bodhi & banyan) ---

# Stop any running reinjectors (optional but recommended)
sudo pkill -f af_reinject 2>/dev/null || true

# Delete all egress & ingress filters on eno1
sudo tc filter del dev eno1 egress  2>/dev/null || true
sudo tc filter del dev eno1 ingress 2>/dev/null || true

# Remove the clsact qdisc (removes the egress/ingress hooks)
sudo tc qdisc del dev eno1 clsact   2>/dev/null || true

# (Optional) Remove helper interfaces if you want a totally clean slate
sudo ip link set ifb0 down  2>/dev/null || true
sudo ip link del ifb0       2>/dev/null || true
sudo ip link set auth0 down 2>/dev/null || true
sudo ip link del auth0      2>/dev/null || true

# Verify nothing remains (should show nothing / no filters)
sudo tc -s filter show dev eno1 egress
sudo tc -s filter show dev eno1 ingress
















## NEW BODHI


# IFB + clsact (unchanged)
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# EGRESS (bodhi→banyan): mirror originals (DSCP=0) then DROP (unchanged)
sudo tc filter replace dev eno1 egress pref 100 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# INGRESS (banyan→bodhi replies): add skip_hw here
sudo tc filter replace dev eno1 ingress pref 200 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  action mirred egress mirror dev ifb0 \
  action drop

# TUN for verified delivery (unchanged)
ip link show auth0 >/dev/null 2>&1 || sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0


BANYAN


# IFB + clsact (unchanged)
sudo modprobe ifb
ip link show ifb0 >/dev/null 2>&1 || sudo ip link add ifb0 type ifb
sudo ip link set ifb0 up
sudo tc qdisc add dev eno1 clsact 2>/dev/null || true

# INGRESS (bodhi→banyan): add skip_hw here
sudo tc filter replace dev eno1 ingress pref 100 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.2 dst_ip 192.168.200.1 dst_port 9999 \
  action mirred egress mirror dev ifb0 \
  action drop

# EGRESS (banyan→bodhi replies): mirror originals (DSCP=0) then DROP (unchanged)
sudo tc filter replace dev eno1 egress pref 200 protocol ip \
  flower skip_hw ip_proto udp \
  src_ip 192.168.200.1 src_port 9999 dst_ip 192.168.200.2 \
  ip_tos 0x00/0xFC \
  action mirred egress mirror dev ifb0 \
  action drop

# TUN for verified delivery (unchanged)
ip link show auth0 >/dev/null 2>&1 || sudo ip tuntap add dev auth0 mode tun
sudo ip link set auth0 up
sudo sysctl -w net.ipv4.conf.auth0.accept_local=1
sudo sysctl -w net.ipv4.conf.auth0.rp_filter=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0