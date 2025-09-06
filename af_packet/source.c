// af_reinject.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

static const char *RX_IFACE = "ifb0"; // receive mirrored originals here
static const char *TX_IFACE = "eno1"; // transmit reinjected copies here
static const char *DST_IP_S = "192.168.200.1";
static const uint16_t DST_PORT = 9999;

static const uint8_t MARK_BYTES[] = {'R', 'I', 'N', 'J'}; // payload marker
#define MARK_LEN (sizeof(MARK_BYTES))

// -------- checksum helpers --------
static uint16_t ip_checksum(const void *vdata, size_t length)
{
    const uint8_t *data = vdata;
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2)
    {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    if (length & 1)
    {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    return htons(~acc);
}

static uint16_t udp_checksum(const uint8_t *iphdr, const uint8_t *udphdr, size_t udp_len)
{
    // Pseudo-header + UDP header + payload
    uint32_t acc = 0;

    // Source and dest IP
    for (int i = 12; i < 20; i += 2)
    {
        acc += (iphdr[i] << 8) | iphdr[i + 1];
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    // Protocol + UDP length
    acc += 17; // UDP protocol
    if (acc > 0xffff)
        acc -= 0xffff;
    acc += udp_len;
    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);

    // UDP header + payload bytes
    for (size_t i = 0; i + 1 < udp_len; i += 2)
    {
        uint16_t word = (udphdr[i] << 8) | udphdr[i + 1];
        acc += word;
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    if (udp_len & 1)
    { // pad last byte
        uint16_t word = (udphdr[udp_len - 1] << 8);
        acc += word;
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    return htons(~acc & 0xffff);
}

// -------- parser for IPv4/UDP within Ethernet(+optional VLAN) --------
struct parsed
{
    size_t l2_off, l3_off, l4_off, pay_off;
    size_t frame_len;
    uint16_t ethertype;
    uint8_t ihl;
    uint16_t ip_tot_len;
    uint16_t udp_len;
    uint16_t sport, dport;
    uint8_t tos, ttl;
    uint8_t *eth; // begin frame
    uint8_t *ip;
    uint8_t *udp;
    uint8_t *payload;
    uint8_t dst_mac[6];
};

static int parse_ipv4_udp(uint8_t *f, ssize_t n, struct parsed *out)
{
    if (n < 14)
        return 0;
    uint16_t et = (f[12] << 8) | f[13];
    size_t l2 = 14;

    if (et == 0x8100 || et == 0x88A8)
    { // VLAN/QinQ
        if (n < 18)
            return 0;
        et = (f[16] << 8) | f[17];
        l2 += 4;
    }
    if (et != 0x0800)
        return 0; // IPv4

    if (n < (ssize_t)(l2 + 20))
        return 0;
    uint8_t ihl = (f[l2] & 0x0F) * 4;
    if (ihl < 20 || n < (ssize_t)(l2 + ihl + 8))
        return 0;
    if (f[l2 + 9] != 17)
        return 0; // UDP

    uint16_t dport = (f[l2 + ihl + 2] << 8) | f[l2 + ihl + 3];
    struct in_addr dst_ip;
    memcpy(&dst_ip, f + l2 + 16, 4);
    char dst_ip_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_ip, dst_ip_s, sizeof(dst_ip_s));

    if (strcmp(dst_ip_s, DST_IP_S) != 0 || dport != DST_PORT)
        return 0;

    out->l2_off = 0;
    out->l3_off = l2;
    out->l4_off = l2 + ihl;
    out->pay_off = out->l4_off + 8;
    out->frame_len = n;
    out->ethertype = et;
    out->ihl = ihl;
    out->ip_tot_len = (f[l2 + 2] << 8) | f[l2 + 3];
    out->udp_len = (f[out->l4_off + 4] << 8) | f[out->l4_off + 5];
    out->sport = (f[out->l4_off] << 8) | f[out->l4_off + 1];
    out->dport = dport;
    out->eth = f;
    out->ip = f + l2;
    out->udp = f + out->l4_off;
    out->payload = f + out->pay_off;
    out->tos = f[l2 + 1];
    out->ttl = f[l2 + 8];
    memcpy(out->dst_mac, f, 6); // first 6 bytes of frame (destination MAC)
    return 1;
}

static int payload_has_marker(const struct parsed *P, const uint8_t *frame)
{
    int pay_len = (int)P->udp_len - 8;
    if (pay_len < (int)MARK_LEN)
        return 0;
    const uint8_t *tail = frame + P->pay_off + pay_len - MARK_LEN;
    return (memcmp(tail, MARK_BYTES, MARK_LEN) == 0);
}

int main(void)
{
    int rx_ifindex = if_nametoindex(RX_IFACE);
    if (!rx_ifindex)
    {
        perror("if_nametoindex(RX)");
        return 1;
    }
    int tx_ifindex = if_nametoindex(TX_IFACE);
    if (!tx_ifindex)
    {
        perror("if_nametoindex(TX)");
        return 1;
    }

    int rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx < 0)
    {
        perror("socket rx");
        return 1;
    }
    struct sockaddr_ll rxbind = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = rx_ifindex,
    };
    if (bind(rx, (struct sockaddr *)&rxbind, sizeof(rxbind)) < 0)
    {
        perror("bind rx");
        return 1;
    }

    int tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tx < 0)
    {
        perror("socket tx");
        return 1;
    }

    struct sockaddr_ll txbind = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = tx_ifindex,
    };
    if (bind(tx, (struct sockaddr *)&txbind, sizeof(txbind)) < 0)
    {
        perror("bind tx");
        return 1;
    }
    int snd = 4 * 1024 * 1024; // 4 MB
    setsockopt(tx, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    printf("[reinjector] RX=%s (ifb mirror of originals), TX=%s; mark DSCP=EF, TTL=63, payload+=\"RINJ\"\n",
           RX_IFACE, TX_IFACE);

    uint8_t inbuf[65536];
    uint8_t outbuf[65536];

    while (1)
    {
        ssize_t n = recvfrom(rx, inbuf, sizeof(inbuf), 0, NULL, NULL);
        if (n <= 0)
        {
            if (errno == EINTR)
                continue;
            perror("recvfrom");
            break;
        }

        struct parsed P;
        if (!parse_ipv4_udp(inbuf, n, &P))
            continue;

        // ---- LOOP AVOIDANCE ----
        // Only act on DSCP==0 (originals) and skip frames that look like our reinjected copies
        if ((P.tos & 0xFC) != 0)
            continue; // DSCP not zero => likely reinjected/other, skip
        if (P.ttl == 63)
            continue; // our chosen reinject TTL, skip
        if (payload_has_marker(&P, inbuf))
            continue; // already has marker, skip
        // ------------------------

        // Build output frame = original + MARK_LEN (ensure MTU safety)
        size_t out_len = P.frame_len + MARK_LEN;
        if (out_len > sizeof(outbuf))
            continue;

        memcpy(outbuf, inbuf, P.frame_len);
        memcpy(outbuf + P.frame_len, MARK_BYTES, MARK_LEN);

        uint8_t *eth = outbuf + P.l2_off;
        uint8_t *ip = outbuf + P.l3_off;
        uint8_t *udp = outbuf + P.l4_off;

        // Update IP total length and UDP length (+MARK_LEN)
        uint16_t new_ip_tot = P.ip_tot_len + MARK_LEN;
        uint16_t new_udp_len = P.udp_len + MARK_LEN;
        ip[2] = (new_ip_tot >> 8) & 0xFF;
        ip[3] = new_ip_tot & 0xFF;
        udp[4] = (new_udp_len >> 8) & 0xFF;
        udp[5] = new_udp_len & 0xFF;

        // Mark DSCP=EF (0xb8) while preserving ECN (lowest 2 bits)
        ip[1] = (ip[1] & 0x03) | 0xB8;
        // Set TTL=63
        ip[8] = 63;

        // Recompute checksums
        ip[10] = ip[11] = 0;
        uint16_t ip_chk = ip_checksum(ip, P.ihl);
        ip[10] = (ip_chk >> 8) & 0xFF;
        ip[11] = ip_chk & 0xFF;

        udp[6] = udp[7] = 0;
        uint16_t udp_chk = udp_checksum(ip, udp, new_udp_len);
        udp[6] = (udp_chk >> 8) & 0xFF;
        udp[7] = udp_chk & 0xFF;

        // Send out using original dest MAC on TX_IFACE
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_IP),
            .sll_ifindex = tx_ifindex,
            .sll_halen = ETH_ALEN,
        };
        memcpy(sll.sll_addr, eth, 6); // dest MAC from original frame

        ssize_t sent = sendto(tx, outbuf, out_len, 0, (struct sockaddr *)&sll, sizeof(sll));
        if (sent < 0)
        {
            perror("sendto");
            continue;
        }

        char src_ip_s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, P.ip + 12, src_ip_s, sizeof(src_ip_s));
        printf("reinj: %s -> %s:%u, out_len=%zd, DSCP=EF, TTL=63\n",
               src_ip_s, DST_IP_S, DST_PORT, sent);
        fflush(stdout);
    }

    close(rx);
    close(tx);
    return 0;
}