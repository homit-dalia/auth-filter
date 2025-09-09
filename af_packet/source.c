// af_reinject.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

// ------------ config ------------
static const char *RX_IFACE = "ifb0";   // where mirrored copies land
static const char *TX_IFACE = "eno1";   // where we transmit reinjected frames (source mode)
static const char *TUN_IFACE = "auth0"; // where we inject to host stack (dest mode, L3 only)
static const char *DST_IP_S = "192.168.200.1";
static const uint16_t DST_PORT = 9999;
// Strip the UOPT on the destination before forwarding? (1=yes, 0=keep)
#define STRIP_UOPT_ON_DEST 1
// --------------------------------

// --- runtime mode ---
enum run_mode
{
    MODE_SOURCE = 0,
    MODE_DEST = 1
};

// Canonicalize UDP header for hashing: zero length and checksum (bytes 4..7)
static inline void make_udp_canonical8(const uint8_t *udp, uint8_t out[8])
{
    memcpy(out, udp, 8);
    out[4] = 0;
    out[5] = 0; // len
    out[6] = 0;
    out[7] = 0; // csum
}

// prompt/parse mode (flag --mode source|dest or interactive)
static enum run_mode pick_mode(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc)
        {
            if (!strcmp(argv[i + 1], "source"))
                return MODE_SOURCE;
            if (!strcmp(argv[i + 1], "dest"))
                return MODE_DEST;
        }
    }
    char buf[32] = {0};
    fprintf(stdout, "Run as [source/dest]? ");
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin))
    {
        if (strncasecmp(buf, "dest", 4) == 0)
            return MODE_DEST;
    }
    return MODE_SOURCE;
}

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
    return (uint16_t)(~acc & 0xFFFF);
}

static uint16_t udp_checksum(const uint8_t *iphdr, const uint8_t *udphdr, size_t udp_len)
{
    uint32_t acc = 0;
    for (int i = 12; i < 20; i += 2)
    { // src/dst ip
        acc += (iphdr[i] << 8) | iphdr[i + 1];
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    acc += 17;
    if (acc > 0xffff)
        acc -= 0xffff; // proto
    acc += udp_len;
    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);

    for (size_t i = 0; i + 1 < udp_len; i += 2)
    {
        uint16_t word = (udphdr[i] << 8) | udphdr[i + 1];
        acc += word;
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    if (udp_len & 1)
    {
        uint16_t word = (udphdr[udp_len - 1] << 8);
        acc += word;
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    return (uint16_t)(~acc & 0xFFFF);
}

// Canonicalize IP header bytes for hashing: zero fields that change in transit
// Zeros: TOS/DSCP+ECN (1), Total Length (2-3), TTL (8), Header Checksum (10-11)
static size_t make_ip_canonical(const uint8_t *ip, size_t ihl, uint8_t *out60)
{
    if (ihl > 60)
        return 0;
    memcpy(out60, ip, ihl);
    out60[1] = 0; // TOS
    out60[2] = 0;
    out60[3] = 0; // Total Length
    out60[8] = 0; // TTL
    out60[10] = 0;
    out60[11] = 0; // checksum
    return ihl;
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
    uint8_t *eth;
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

    // VLAN/QinQ (single tag handled)
    if (et == 0x8100 || et == 0x88A8)
    {
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
    memcpy(out->dst_mac, f, 6);
    return 1;
}

// -------- our custom "UDP option" TLV (appended to payload) --------
// Layout: "UOPT"(4) | kind=1 (1B) | len=32 (1B) | digest[32]
#pragma pack(push, 1)
struct udp_opt_sha256
{
    char magic[4];
    uint8_t kind;
    uint8_t len;
    uint8_t digest[32];
};
#pragma pack(pop)
#define UOPT_KIND_SHA256 1
#define UOPT_HDR_LEN (sizeof(struct udp_opt_sha256))

// Try to read our TLV from the end of the UDP payload.
static int extract_uopt_tail(const struct parsed *P, const uint8_t *frame,
                             struct udp_opt_sha256 *opt_out)
{
    int pay_len = (int)P->udp_len - 8;
    if (pay_len < (int)UOPT_HDR_LEN)
        return 0;
    const uint8_t *tail = frame + P->pay_off + pay_len - UOPT_HDR_LEN;
    struct udp_opt_sha256 tmp;
    memcpy(&tmp, tail, UOPT_HDR_LEN);
    if (memcmp(tmp.magic, "UOPT", 4) != 0)
        return 0;
    if (tmp.kind != UOPT_KIND_SHA256)
        return 0;
    if (tmp.len != 32)
        return 0;
    if (opt_out)
        *opt_out = tmp;
    return 1;
}

// ---- per-flow key lookup (returns a static 64B key for now) ----
static const unsigned char *
key_lookup(const struct in_addr *saddr,
           const struct in_addr *daddr,
           uint16_t sport, uint16_t dport,
           size_t *key_len_out)
{
    (void)saddr;
    (void)daddr;
    (void)sport;
    (void)dport;
    static const unsigned char KEY[] =
        "thisisaverysecure64bytehmacauthenticationkey12345678901234567890";
    if (key_len_out)
        *key_len_out = sizeof(KEY); // use full 64 bytes
    return KEY;
}

// core: in SOURCE mode, append TLV & mark; in DEST mode, verify (and optionally strip TLV)
static size_t process_packet(enum run_mode mode,
                             const struct parsed *P,
                             const uint8_t *in, size_t in_len,
                             uint8_t *out, size_t out_cap,
                             int *verified_ok)
{
    if (in_len > out_cap)
        return 0;
    memcpy(out, in, in_len);
    size_t out_len = in_len;

    uint8_t *ip = out + P->l3_off;
    uint8_t *udp = out + P->l4_off;

    // Canonicalize IP header for hashing
    uint8_t ipcanon[60];
    size_t canon_len = make_ip_canonical(ip, P->ihl, ipcanon);
    if (!canon_len)
        return 0;

    // Resolve key
    struct in_addr src_ip, dst_ip;
    memcpy(&src_ip, ip + 12, 4);
    memcpy(&dst_ip, ip + 16, 4);
    size_t key_len = 0;
    const unsigned char *key = key_lookup(&src_ip, &dst_ip, P->sport, P->dport, &key_len);

    // Build digest = SHA256( key || canon(IP) || canonical UDP header 8B )
    uint8_t digest[32];
    SHA256_CTX ctx;

    if (mode == MODE_SOURCE)
    {
        SHA256_Init(&ctx);
        if (key && key_len)
            SHA256_Update(&ctx, key, key_len);
        SHA256_Update(&ctx, ipcanon, canon_len);
        uint8_t udpcanon[8];
        make_udp_canonical8(udp, udpcanon);
        SHA256_Update(&ctx, udpcanon, 8);
        SHA256_Final(digest, &ctx);

        // Append TLV
        if (out_len + UOPT_HDR_LEN > out_cap)
            return 0;
        struct udp_opt_sha256 opt;
        memcpy(opt.magic, "UOPT", 4);
        opt.kind = UOPT_KIND_SHA256;
        opt.len = 32;
        memcpy(opt.digest, digest, 32);
        memcpy(out + out_len, &opt, UOPT_HDR_LEN);
        out_len += UOPT_HDR_LEN;

        // Bump lengths
        uint16_t new_ip_tot = (uint16_t)(P->ip_tot_len + UOPT_HDR_LEN);
        uint16_t new_udp_len = (uint16_t)(P->udp_len + UOPT_HDR_LEN);
        ip[2] = (new_ip_tot >> 8) & 0xFF;
        ip[3] = new_ip_tot & 0xFF;
        udp[4] = (new_udp_len >> 8) & 0xFF;
        udp[5] = new_udp_len & 0xFF;

        // Mark + recompute checksums
        ip[1] = (ip[1] & 0x03) | 0xB8; // DSCP=EF
        ip[8] = 63;                    // TTL=63
        ip[10] = ip[11] = 0;
        uint16_t ip_chk = ip_checksum(ip, P->ihl);
        ip[10] = (ip_chk >> 8) & 0xFF;
        ip[11] = ip_chk & 0xFF;

        udp[6] = udp[7] = 0;
        uint16_t udp_chk = udp_checksum(ip, udp, new_udp_len);
        udp[6] = (udp_chk >> 8) & 0xFF;
        udp[7] = udp_chk & 0xFF;

        if (verified_ok)
            *verified_ok = 1;
        return out_len;
    }
    else
    {
        // DEST: verify existing TLV
        struct udp_opt_sha256 got;
        if (!extract_uopt_tail(P, in, &got))
        {
            if (verified_ok)
                *verified_ok = 0;
            fprintf(stderr, "reject: missing UOPT TLV\n");
            return 0;
        }

        SHA256_Init(&ctx);
        if (key && key_len)
            SHA256_Update(&ctx, key, key_len);
        SHA256_Update(&ctx, ipcanon, canon_len);
        uint8_t udpcanon[8];
        make_udp_canonical8(udp, udpcanon);
        SHA256_Update(&ctx, udpcanon, 8);
        SHA256_Final(digest, &ctx);

        int ok = (memcmp(got.digest, digest, 32) == 0);
        if (!ok)
        {
            if (verified_ok)
                *verified_ok = 0;
            fprintf(stderr, "reject: hash mismatch\n");
            return 0;
        }
        if (verified_ok)
            *verified_ok = 1;

        if (STRIP_UOPT_ON_DEST)
        {
            if (out_len < UOPT_HDR_LEN)
                return 0;
            out_len -= UOPT_HDR_LEN;

            // Shrink lengths
            uint16_t new_ip_tot = (uint16_t)(P->ip_tot_len - UOPT_HDR_LEN);
            uint16_t new_udp_len = (uint16_t)(P->udp_len - UOPT_HDR_LEN);
            ip[2] = (new_ip_tot >> 8) & 0xFF;
            ip[3] = new_ip_tot & 0xFF;
            udp[4] = (new_udp_len >> 8) & 0xFF;
            udp[5] = new_udp_len & 0xFF;

            // Recompute checksums (keep DSCP/TTL as seen)
            ip[10] = ip[11] = 0;
            uint16_t ip_chk = ip_checksum(ip, P->ihl);
            ip[10] = (ip_chk >> 8) & 0xFF;
            ip[11] = ip_chk & 0xFF;

            udp[6] = udp[7] = 0;
            uint16_t udp_chk = udp_checksum(ip, udp, new_udp_len);
            udp[6] = (udp_chk >> 8) & 0xFF;
            udp[7] = udp_chk & 0xFF;
        }
        return out_len;
    }
}

// ----- TUN helper (dest mode) -----
static int tun_open(const char *name)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // L3 IPv4/IPv6, no extra proto info
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    enum run_mode MODE = pick_mode(argc, argv);

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

    int tx = -1;
    if (MODE == MODE_SOURCE)
    {
        tx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
        int snd = 4 * 1024 * 1024; // TX buffer
        setsockopt(tx, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    }

    int tunfd = -1;
    if (MODE == MODE_DEST)
    {
        tunfd = tun_open(TUN_IFACE);
        if (tunfd < 0)
        {
            fprintf(stderr, "Failed to open TUN %s. Did you create it? (ip tuntap add dev %s mode tun)\n",
                    TUN_IFACE, TUN_IFACE);
            return 1;
        }
    }

    printf("[reinjector] mode=%s RX=%s, TX=%s%s; UOPT=SHA256(key||canonIP||UDPhdr)\n",
           (MODE == MODE_SOURCE ? "source" : "dest"),
           RX_IFACE,
           (MODE == MODE_SOURCE ? TX_IFACE : "(none)"),
           (MODE == MODE_DEST ? ", TUN=" : ""),
           (MODE == MODE_DEST ? TUN_IFACE : ""));

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

        // Loop avoidance:
        if (MODE == MODE_SOURCE)
        {
            if ((P.tos & 0xFC) != 0)
                continue; // non-zero DSCP => skip
            if (P.ttl == 63)
                continue; // our own copies => skip
            struct udp_opt_sha256 tmp;
            if (extract_uopt_tail(&P, inbuf, &tmp))
                continue; // already has UOPT
        }

        int verified_ok = 0;
        size_t out_len = process_packet(MODE, &P, inbuf, (size_t)n, outbuf, sizeof(outbuf), &verified_ok);

        if (MODE == MODE_DEST)
        {
            if (!out_len || !verified_ok)
            {
                char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, P.ip + 12, s, sizeof(s));
                inet_ntop(AF_INET, P.ip + 16, d, sizeof(d));
                fprintf(stderr, "reject: %s:%u -> %s:%u (hash mismatch or missing UOPT)\n",
                        s, P.sport, d, P.dport);
                fflush(stderr);
                continue;
            }
        }
        else
        {
            if (!out_len)
                continue;
        }

        if (MODE == MODE_SOURCE)
        {
            // Send out via TX_IFACE (use dest MAC from original frame)
            struct sockaddr_ll sll = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = tx_ifindex,
                .sll_halen = ETH_ALEN,
            };
            memcpy(sll.sll_addr, inbuf, 6);

            ssize_t sent = sendto(tx, outbuf, out_len, 0, (struct sockaddr *)&sll, sizeof(sll));
            if (sent < 0)
            {
                perror("sendto");
                continue;
            }

            char src_ip_s[INET_ADDRSTRLEN], dst_ip_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, P.ip + 12, src_ip_s, sizeof(src_ip_s));
            inet_ntop(AF_INET, P.ip + 16, dst_ip_s, sizeof(dst_ip_s));
            printf("src reinj: %s -> %s:%u, +UOPT(sha256), out_len=%zd\n",
                   src_ip_s, dst_ip_s, P.dport, sent);
            fflush(stdout);
        }
        else
        {
            // DEST: inject into local INPUT via TUN (L3 write: IP header + payload)
            uint8_t *ip = outbuf + P.l3_off;
            uint16_t ip_tot = ((uint16_t)ip[2] << 8) | ip[3];
            ssize_t w = write(tunfd, ip, ip_tot);
            if (w < 0)
            {
                perror("write(tun)");
                continue;
            }

            char src_ip_s[INET_ADDRSTRLEN], dst_ip_s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ip + 12, src_ip_s, sizeof(src_ip_s));
            inet_ntop(AF_INET, ip + 16, dst_ip_s, sizeof(dst_ip_s));
            printf("dst accept→INPUT: %s -> %s:%u, %sUOPT, ip_len=%u\n",
                   src_ip_s, dst_ip_s, P.dport,
                   STRIP_UOPT_ON_DEST ? "stripped " : "kept ", ip_tot);
            fflush(stdout);
        }
    }

    if (tunfd >= 0)
        close(tunfd);
    if (tx >= 0)
        close(tx);
    close(rx);
    return 0;
}