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