// source.c (af_reinject)
// Build example:
//   gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
//       -o af_reinject \
//       source.c ../ip_lookup_cpu/src/radix_trie_api.c \
//       -lcrypto
#define _GNU_SOURCE

#include "radix_trie_api.h"

#ifndef PREFIX_CSV
#define PREFIX_CSV "../ip_lookup_cpu/src/data/prefix_table.csv"
#endif

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
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h> // NEW: for enumerating local IPv4s

#ifndef LOCAL_IP
// Override per-host at build time, e.g. -DLOCAL_IP="\"192.168.200.1\""
#define LOCAL_IP "0.0.0.0" // 0.0.0.0 ⇒ don't filter by local IP
#endif

static BinaryTrie *g_trie = NULL;

// ---- spoofing toggle (default: enabled) ----
static int g_enable_spoof = 1;

// ------------ config ------------
static const char *RX_IFACE = "eno1";   // where mirrored copies land
static const char *TX_IFACE = "eno1";   // where we transmit reinjected frames (source mode)
static const char *TUN_IFACE = "auth0"; // where we inject to host stack (dest mode, L3 only)
static const uint16_t DST_PORT = 9999;
// Strip the UOPT on the destination before forwarding? (1=yes, 0=keep)
#define STRIP_UOPT_ON_DEST 1
// --------------------------------

// ---- iperf3 control peer tracking (sender side) ----
static uint32_t g_ctrl_ip_be = 0; // last TCP control peer (network order)
static time_t g_ctrl_ip_ts = 0;   // when we learned it
static int g_ctrl_ip_ttl = 10;    // seconds to keep it "fresh"

// --- runtime mode ---
enum run_mode
{
    MODE_SOURCE = 0,
    MODE_DEST = 1
};

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

// -------- boolean helpers for spoof toggle --------
static int parse_bool(const char *s, int defval)
{
    if (!s || !*s)
        return defval;
    char buf[16];
    size_t i = 0;
    for (; s[i] && i < sizeof(buf) - 1; ++i)
        buf[i] = (char)tolower((unsigned char)s[i]);
    buf[i] = 0;
    if (!strcmp(buf, "1") || !strcmp(buf, "on") || !strcmp(buf, "true") || !strcmp(buf, "yes"))
        return 1;
    if (!strcmp(buf, "0") || !strcmp(buf, "off") || !strcmp(buf, "false") || !strcmp(buf, "no"))
        return 0;
    return defval;
}

static void apply_spoof_overrides_from_env_argv(int argc, char **argv)
{
    const char *ev = getenv("SPOOF");
    g_enable_spoof = parse_bool(ev, g_enable_spoof);

    for (int i = 1; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--no-spoof"))
        {
            g_enable_spoof = 0;
        }
        else if (!strcmp(argv[i], "--spoof"))
        {
            // bare --spoof means enable; also support "--spoof on|off"
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                g_enable_spoof = parse_bool(argv[i + 1], g_enable_spoof);
                ++i;
            }
            else
            {
                g_enable_spoof = 1;
            }
        }
        else if (!strncmp(argv[i], "--spoof=", 8))
        {
            g_enable_spoof = parse_bool(argv[i] + 8, g_enable_spoof);
        }
    }
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

    // accept either direction if either port is DST_PORT
    uint16_t sport = (f[l2 + ihl] << 8) | f[l2 + ihl + 1];
    uint16_t dport = (f[l2 + ihl + 2] << 8) | f[l2 + ihl + 3];
    if (sport != DST_PORT && dport != DST_PORT)
        return 0;

    // Fill the parsed struct
    out->l2_off = 0;
    out->l3_off = l2;
    out->l4_off = l2 + ihl;
    out->pay_off = out->l4_off + 8;
    out->frame_len = n;
    out->ethertype = et;
    out->ihl = ihl;
    out->ip_tot_len = (f[l2 + 2] << 8) | f[l2 + 3];
    out->udp_len = (f[out->l4_off + 4] << 8) | f[out->l4_off + 5];
    out->sport = sport;
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

// Learn TCP control peer (port DST_PORT). We only need src IP.
// REPLACE your maybe_learn_ctrl_from_tcp_9999() with this version
static void maybe_learn_ctrl_from_tcp_9999(const uint8_t *f, ssize_t n)
{
    if (n < 14)
        return;

    uint16_t et = (f[12] << 8) | f[13];
    size_t l2 = 14;

    // VLAN/QinQ (single tag)
    if (et == 0x8100 || et == 0x88A8)
    {
        if (n < 18)
            return;
        et = (f[16] << 8) | f[17];
        l2 += 4;
    }
    if (et != 0x0800)
        return; // IPv4 only
    if (n < (ssize_t)(l2 + 20))
        return;

    const uint8_t *ip = f + l2;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || n < (ssize_t)(l2 + ihl + 20))
        return;
    if (ip[9] != 6)
        return; // TCP only

    const uint8_t *tcp = ip + ihl;
    uint16_t sport = (tcp[0] << 8) | tcp[1];
    uint16_t dport = (tcp[2] << 8) | tcp[3];
    if (sport != DST_PORT && dport != DST_PORT)
        return;

    // Learn from either direction:
    // - client->server  (dport==DST_PORT) ⇒ peer is ip.src (client)
    // - server->client  (sport==DST_PORT) ⇒ peer is ip.dst (client)
    uint32_t peer_be = 0;
    if (dport == DST_PORT)
    {
        memcpy(&peer_be, ip + 12, 4); // ip.src
    }
    else
    {                                 // sport == DST_PORT
        memcpy(&peer_be, ip + 16, 4); // ip.dst
    }

    g_ctrl_ip_be = peer_be;
    g_ctrl_ip_ts = time(NULL);
    // optional debug:
    // struct in_addr a; a.s_addr = g_ctrl_ip_be;
    // fprintf(stderr, "ctrl-learn peer=%s\n", inet_ntoa(a));
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

// ---- per-flow key lookup (returns a derived 64B key) ----
// Derive 64B per-flow key = Expand( SHA256(base_key || src_ip || sport || dport) )
static const unsigned char *
key_lookup(const struct in_addr *saddr,
           const struct in_addr *_daddr, // unused for derivation, but kept for signature symmetry
           uint16_t sport, uint16_t dport,
           size_t *key_len_out)
{
    static unsigned char DERIVED[64]; // single-threaded program => ok

    // 1) LPM on source IP (host order)
    uint32_t src_hbo = ntohl(saddr->s_addr);
    const unsigned char *base = NULL;
    size_t base_len = 0;
    if (!g_trie || !rt_lookup_key(g_trie, src_hbo, &base, &base_len) || base_len == 0)
    {
        // no match => signal missing key
        if (key_len_out)
            *key_len_out = 0;
        return NULL;
    }

    // 2) Derive per-flow material using ports in network order (wire order)
    //    info = src_ip_be(4) || sport_be(2) || dport_be(2)
    unsigned char info[8];
    memcpy(info, &saddr->s_addr, 4);
    info[4] = (uint8_t)(sport >> 8);
    info[5] = (uint8_t)(sport & 0xFF);
    info[6] = (uint8_t)(dport >> 8);
    info[7] = (uint8_t)(dport & 0xFF);

    // F = SHA256(base || info || 0x01) || SHA256(base || info || 0x02)
    unsigned char h1[32], h2[32];
    unsigned char ib1 = 0x01, ib2 = 0x02;
    SHA256_CTX c;

    SHA256_Init(&c);
    SHA256_Update(&c, base, base_len);
    SHA256_Update(&c, info, sizeof(info));
    SHA256_Update(&c, &ib1, 1);
    SHA256_Final(h1, &c);

    SHA256_Init(&c);
    SHA256_Update(&c, base, base_len);
    SHA256_Update(&c, info, sizeof(info));
    SHA256_Update(&c, &ib2, 1);
    SHA256_Final(h2, &c);

    memcpy(DERIVED, h1, 32);
    memcpy(DERIVED + 32, h2, 32);

    if (key_len_out)
        *key_len_out = sizeof(DERIVED);
    return DERIVED;
}

// -------- SPOOF SOURCE: use prefixes from prefix_table.csv --------
typedef struct
{
    uint32_t net_hbo;
    uint8_t len;
} SpoofPref;
static SpoofPref *g_spoof = NULL;
static size_t g_spoof_cnt = 0;

// ---- local IPv4 list (sender side) ----
typedef struct
{
    uint32_t be;
} LocalIpBe; // stored in network byte order
static LocalIpBe *g_local_ips = NULL;
static size_t g_local_ip_cnt = 0;

static inline uint32_t mask_from_len(uint8_t len)
{
    return (len == 0) ? 0U : (~0U << (32 - len));
}

static void trim_eol(char *s)
{
    if (!s)
        return;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        --e;
    *e = '\0';
}

static void load_spoof_prefixes_from_prefix_csv(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, "open failed: %s\n", path);
        return;
    }

    char line[8192];
    int first = 1;
    while (fgets(line, sizeof(line), f))
    {
        trim_eol(line);
        char *p = line;
        while (*p == ' ' || *p == '\t')
            ++p;
        if (!*p || *p == '#')
            continue;

        if (first)
        { // header?
            first = 0;
            if (!isdigit((unsigned char)*p))
                continue;
        }

        // prefix,key
        char *comma = strchr(p, ',');
        if (comma)
            *comma = '\0';
        char *slash = strchr(p, '/');
        if (!slash)
            continue;
        *slash = '\0';
        const char *ip_s = p;
        int plen = atoi(slash + 1);
        if (plen < 0 || plen > 32)
            continue;

        struct in_addr a;
        if (inet_pton(AF_INET, ip_s, &a) != 1)
            continue;
        uint32_t net_hbo = ntohl(a.s_addr) & mask_from_len((uint8_t)plen);

        SpoofPref *tmp = (SpoofPref *)realloc(g_spoof, (g_spoof_cnt + 1) * sizeof(SpoofPref));
        if (!tmp)
        {
            fclose(f);
            return;
        }
        g_spoof = tmp;
        g_spoof[g_spoof_cnt].net_hbo = net_hbo;
        g_spoof[g_spoof_cnt].len = (uint8_t)plen;
        g_spoof_cnt++;
    }
    fclose(f);

    if (g_spoof_cnt == 0)
    {
        free(g_spoof);
        g_spoof = NULL;
        fprintf(stderr, "spoof: no prefixes found in %s (spoofing disabled)\n", path);
    }
    else
    {
        fprintf(stderr, "spoof: loaded %zu prefixes from %s\n", g_spoof_cnt, path);
    }
}

// simple LCG RNG
static inline uint32_t lcg_next(void)
{
    static uint32_t s = 0;
    if (!s)
        s = (uint32_t)time(NULL) ^ (uint32_t)getpid() ^ 0x9e3779b9u;
    s = 1664525u * s + 1013904223u;
    return s;
}

static inline uint32_t random_ip_in_prefix_be(const SpoofPref *P)
{
    if (P->len == 32)
    {
        return htonl(P->net_hbo);
    }
    uint8_t host_bits = 32 - P->len;
    uint32_t host_mask = (host_bits == 32) ? 0xFFFFFFFFu : ((1u << host_bits) - 1u);
    uint32_t rnd = lcg_next() & host_mask;
    uint32_t ip_hbo = (P->net_hbo & mask_from_len(P->len)) | rnd;
    return htonl(ip_hbo);
}

// Is a candidate address network or broadcast for the chosen prefix?
static inline int ip_is_net_or_bcast_be(uint32_t be, const SpoofPref *P)
{
    uint32_t h = ntohl(be);
    uint32_t mask = mask_from_len(P->len);
    uint32_t net = P->net_hbo & mask;
    uint32_t bcast = net | ~mask;
    return (h == net) || (h == bcast);
}

// Load all local IPv4 addresses (in BE) so we don't spoof ourselves
static void load_local_ipv4s(void)
{
    struct ifaddrs *ifa = NULL, *it = NULL;
    if (getifaddrs(&ifa) != 0)
    {
        perror("getifaddrs");
        return;
    }
    // first pass: count
    size_t cnt = 0;
    for (it = ifa; it; it = it->ifa_next)
    {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET)
            continue;
        cnt++;
    }
    if (cnt)
    {
        g_local_ips = (LocalIpBe *)calloc(cnt, sizeof(LocalIpBe));
        if (!g_local_ips)
        {
            freeifaddrs(ifa);
            return;
        }
    }
    // second pass: copy
    for (it = ifa; it; it = it->ifa_next)
    {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET)
            continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)it->ifa_addr;
        if (sa->sin_addr.s_addr == 0)
            continue;                                           // skip 0.0.0.0
        g_local_ips[g_local_ip_cnt++].be = sa->sin_addr.s_addr; // already BE
    }
    freeifaddrs(ifa);
    fprintf(stderr, "local: learned %zu IPv4 addresses\n", g_local_ip_cnt);
}

static inline int is_local_ip_be(uint32_t be)
{
    for (size_t i = 0; i < g_local_ip_cnt; ++i)
        if (g_local_ips[i].be == be)
            return 1;
    return 0;
}

// Canonicalize UDP header for hashing: zero length and checksum (bytes 4..7)
static inline void make_udp_canonical8(const uint8_t *udp, uint8_t out[8])
{
    memcpy(out, udp, 8);
    out[4] = 0;
    out[5] = 0; // len
    out[6] = 0;
    out[7] = 0; // csum
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
    uint8_t digest[32];
    SHA256_CTX ctx;

    if (mode == MODE_SOURCE)
    {
        // (1) spoof source from prefix_table.csv (only if enabled and prefixes loaded)
        // (1) spoof source from prefix_table.csv (only if enabled and prefixes loaded)
        //     Never pick: our local IPs, the packet's destination IP, or net/broadcast of the prefix.
        // (1) spoof source (only if enabled and prefixes loaded).
        //     Prefer the most-recent TCP control peer to satisfy iperf3's session matching.
        //     We still avoid: our local IPs, the dst IP, and net/bcast.
        if (g_enable_spoof && g_spoof_cnt > 0)
        {
            uint32_t dst_be;
            memcpy(&dst_be, ip + 16, 4);
            int set = 0;
            time_t now = time(NULL);

            // A. try the learned TCP control peer first (if recent)
            if (g_ctrl_ip_be && (now - g_ctrl_ip_ts) <= g_ctrl_ip_ttl)
            {
                // Must also fall inside *some* spoof prefix so key_lookup will succeed.
                // If it doesn't, we'll try random below.
                uint32_t cand_be = g_ctrl_ip_be;
                if (cand_be != dst_be && !is_local_ip_be(cand_be))
                {
                    // Check it's not net/bcast for any prefix that contains it (best-effort)
                    int ok = 1;
                    for (size_t i = 0; i < g_spoof_cnt; ++i)
                    {
                        const SpoofPref *P = &g_spoof[i];
                        uint32_t mask = mask_from_len(P->len);
                        if (((ntohl(cand_be) & mask) == (P->net_hbo & mask)))
                        {
                            if (ip_is_net_or_bcast_be(cand_be, P))
                            {
                                ok = 0;
                            }
                            break;
                        }
                    }
                    if (ok)
                    {
                        memcpy(ip + 12, &cand_be, 4);
                        set = 1;
                    }
                }
            }

            // B. otherwise random from our prefixes (your original behavior)
            for (int tries = 0; !set && tries < 8; ++tries)
            {
                const SpoofPref *sp = &g_spoof[lcg_next() % g_spoof_cnt];
                uint32_t cand_be = random_ip_in_prefix_be(sp);
                if (cand_be == dst_be)
                    continue;
                if (is_local_ip_be(cand_be))
                    continue;
                if (ip_is_net_or_bcast_be(cand_be, sp))
                    continue;
                memcpy(ip + 12, &cand_be, 4);
                set = 1;
            }
            // If we fail to find a safe spoof, we leave the original src and carry on.
        }
        // (2) Canonicalize AFTER spoofing
        size_t canon_len = make_ip_canonical(ip, P->ihl, ipcanon);
        if (!canon_len)
            return 0;

        // (3) Resolve key (based on current source, spoofed or not)
        struct in_addr src_ip, dst_ip;
        memcpy(&src_ip, ip + 12, 4);
        memcpy(&dst_ip, ip + 16, 4);
        size_t key_len = 0;
        const unsigned char *key = key_lookup(&src_ip, &dst_ip, P->sport, P->dport, &key_len);

        if (!key || !key_len)
        {
            // No per-prefix key: just forward the packet as-is (no UOPT),
            // but still mark DSCP/TTL so we won't loop on our own frames.
            ip[1] = (ip[1] & 0x03) | 0xB8; // DSCP = EF
            ip[8] = 63;                    // TTL = 63

            // Recompute checksums for the ORIGINAL lengths (no TLV appended)
            ip[10] = ip[11] = 0;
            uint16_t ip_chk = ip_checksum(ip, P->ihl);
            ip[10] = (ip_chk >> 8) & 0xFF;
            ip[11] = ip_chk & 0xFF;

            udp[6] = udp[7] = 0;
            uint16_t udp_chk = udp_checksum(ip, udp, P->udp_len);
            udp[6] = (udp_chk >> 8) & 0xFF;
            udp[7] = udp_chk & 0xFF;

            if (verified_ok)
                *verified_ok = 1;
            return out_len; // forward, no UOPT
        }

        // (4) Build digest = SHA256( key || canon(IP) || canonical UDP header 8B )
        uint8_t udpcanon[8];
        make_udp_canonical8(udp, udpcanon);
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key, key_len);
        SHA256_Update(&ctx, ipcanon, canon_len);
        SHA256_Update(&ctx, udpcanon, 8);
        SHA256_Final(digest, &ctx);

        // (5) Append TLV
        if (out_len + UOPT_HDR_LEN > out_cap)
            return 0;
        struct udp_opt_sha256 opt;
        memcpy(opt.magic, "UOPT", 4);
        opt.kind = UOPT_KIND_SHA256;
        opt.len = 32;
        memcpy(opt.digest, digest, 32);
        memcpy(out + out_len, &opt, UOPT_HDR_LEN);
        out_len += UOPT_HDR_LEN;

        // (6) Bump lengths
        uint16_t new_ip_tot = (uint16_t)(P->ip_tot_len + UOPT_HDR_LEN);
        uint16_t new_udp_len = (uint16_t)(P->udp_len + UOPT_HDR_LEN);
        ip[2] = (new_ip_tot >> 8) & 0xFF;
        ip[3] = new_ip_tot & 0xFF;
        udp[4] = (new_udp_len >> 8) & 0xFF;
        udp[5] = new_udp_len & 0xFF;

        // (7) Mark + recompute checksums
        ip[1] = (ip[1] & 0x03) | 0xB8; // DSCP=EF
        ip[8] = 63;                    // TTL=63
        ip[10] = ip[11] = 0;
        uint16_t ip_chk = ip_checksum(ip, P->ihl);
        ip[10] = (ip_chk >> 8) & 0xFF;
        ip[11] = ip_chk & 0xFF;

        udp[6] = udp[7] = 0;
        uint16_t udp_chk = udp_checksum(ip, udp, new_udp_len);
        udp[6] = (uint16_t)((udp_chk >> 8) & 0xFF);
        udp[7] = (uint16_t)(udp_chk & 0xFF);

        if (verified_ok)
            *verified_ok = 1;
        return out_len;
    }
    else
    {
        // DEST: verify existing TLV
        size_t canon_len = make_ip_canonical(ip, P->ihl, ipcanon);
        if (!canon_len)
            return 0;

        struct udp_opt_sha256 got;
        if (!extract_uopt_tail(P, in, &got))
        {
            if (verified_ok)
                *verified_ok = 0;
            return 0;
        }

        struct in_addr src_ip, dst_ip;
        memcpy(&src_ip, ip + 12, 4);
        memcpy(&dst_ip, ip + 16, 4);
        size_t key_len = 0;
        const unsigned char *key = key_lookup(&src_ip, &dst_ip, P->sport, P->dport, &key_len);
        if (!key || !key_len)
        {
            if (verified_ok)
                *verified_ok = 0;
            return 0;
        }

        uint8_t udpcanon[8];
        make_udp_canonical8(udp, udpcanon);
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, key, key_len);
        SHA256_Update(&ctx, ipcanon, canon_len);
        SHA256_Update(&ctx, udpcanon, 8);
        SHA256_Final(digest, &ctx);

        int ok = (memcmp(got.digest, digest, 32) == 0);
        if (!ok)
        {
            if (verified_ok)
                *verified_ok = 0;
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
            udp[6] = (uint16_t)((udp_chk >> 8) & 0xFF);
            udp[7] = (uint16_t)(udp_chk & 0xFF);
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

    // Read spoof on/off from env/CLI early
    apply_spoof_overrides_from_env_argv(argc, argv);

    // learn local IPv4s so spoof never chooses our own addresses
    load_local_ipv4s();

    // --- CSV path (simple & safe) ---
    const char *csv_path = getenv("PREFIX_CSV");
    if (!csv_path || !*csv_path)
        csv_path = PREFIX_CSV;

    g_trie = rt_load_csv(csv_path);
    if (!g_trie)
    {
        fprintf(stderr, "Failed to load prefix CSV: %s\n", csv_path);
        return 1;
    }
    fprintf(stderr, "Loaded prefix CSV: %s\n", csv_path);

    // Load spoof prefixes from the SAME prefix CSV (only if spoofing enabled)
    if (g_enable_spoof)
        load_spoof_prefixes_from_prefix_csv(csv_path);
    else
        fprintf(stderr, "spoof: disabled\n");

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

    // Parse LOCAL_IP once; used to ignore mirrored traffic not destined to us.
    struct in_addr me = (struct in_addr){0};
    inet_pton(AF_INET, LOCAL_IP, &me);

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

        // Learn/control: sniff TCP control to :DST_PORT so our spoof can match iperf3's idea of the client
        maybe_learn_ctrl_from_tcp_9999(inbuf, n);

        struct parsed P;
        if (!parse_ipv4_udp(inbuf, n, &P))
            continue;

        if (MODE == MODE_DEST)
        {
            struct in_addr daddr;
            memcpy(&daddr, P.ip + 16, 4); // IPv4 dst

            if (me.s_addr && daddr.s_addr != me.s_addr)
                continue; // not for this host ⇒ ignore silently

            if (P.sport != DST_PORT && P.dport != DST_PORT)
                continue; // neither side is our UDP port ⇒ ignore
        }

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

            if (sendto(tx, outbuf, out_len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
            {
                perror("sendto");
                continue;
            }
        }
        else
        {
            // DEST: inject into local INPUT via TUN (L3 write: IP header + payload)
            uint8_t *ip = outbuf + P.l3_off;
            uint16_t ip_tot = ((uint16_t)ip[2] << 8) | ip[3];
            if (write(tunfd, ip, ip_tot) < 0)
            {
                perror("write(tun)");
                continue;
            }
        }
    }

    if (tunfd >= 0)
        close(tunfd);
    if (tx >= 0)
        close(tx);
    close(rx);

    if (g_trie)
        rt_destroy(g_trie);
    free(g_spoof);

    if (g_local_ips)
        free(g_local_ips);

    return 0;
}