#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/genetlink.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "ovswrap_guard.h"

#define DEFAULT_OBJECT_PATH "/usr/lib/ovswrap-guard/ovswrap_guard.bpf.o"
#define PIN_PATH "/sys/fs/bpf/ovswrap_guard"
#define NEXT_PIN_PATH "/sys/fs/bpf/ovswrap_guard_next"
#define BTF_VMLINUX "/sys/kernel/btf/vmlinux"
#define BTF_OPENVSWITCH "/sys/kernel/btf/openvswitch"
#define MODULE_OPENVSWITCH "/sys/module/openvswitch"
#define MODPROBE_PATH_FILE "/proc/sys/kernel/modprobe"

#ifndef NLA_OK
#define NLA_OK(attribute, remaining) \
	((remaining) >= (int)sizeof(struct nlattr) && \
	 (attribute)->nla_len >= sizeof(struct nlattr) && \
	 (attribute)->nla_len <= (remaining))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(attribute, remaining) \
	((remaining) -= NLA_ALIGN((attribute)->nla_len), \
	 (struct nlattr *)((char *)(attribute) + NLA_ALIGN((attribute)->nla_len)))
#endif

static void btf_unavailable(void)
{
	fputs("OVSwrap guard not installed: required kernel/Open vSwitch BTF "
	      "is unavailable.\n"
	      "Enable/install vmlinux and Open vSwitch module BTF, then retry.\n",
	      stderr);
}

static int read_modprobe_path(char *path, size_t capacity)
{
	char input[PATH_MAX + 2];
	struct stat information;
	size_t first = 0;
	size_t last;
	size_t length;
	size_t used = 0;
	ssize_t received;
	int fd;

	if (!path || capacity < 2)
		return -EINVAL;
	fd = open(MODPROBE_PATH_FILE, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	while (used < sizeof(input)) {
		do {
			received = read(fd, input + used, sizeof(input) - used);
		} while (received < 0 && errno == EINTR);
		if (received < 0) {
			int error = -errno;

			close(fd);
			return error;
		}
		if (!received)
			break;
		used += (size_t)received;
	}
	close(fd);
	if (!used)
		return -EINVAL;
	if (used == sizeof(input))
		return -ENAMETOOLONG;

	last = used;
	while (first < last && isspace((unsigned char)input[first]))
		first++;
	while (last > first && isspace((unsigned char)input[last - 1]))
		last--;
	length = last - first;
	if (!length)
		return -EINVAL;
	if (length >= capacity)
		return -ENAMETOOLONG;
	memcpy(path, input + first, length);
	path[length] = '\0';
	if (path[0] != '/')
		return -EINVAL;
	for (first = 0; first < length; first++) {
		if (iscntrl((unsigned char)path[first]))
			return -EINVAL;
	}
	if (stat(path, &information))
		return -errno;
	if (!S_ISREG(information.st_mode))
		return -EINVAL;
	if (access(path, X_OK))
		return -errno;
	return 0;
}

static int run_modprobe(const char *path, bool remove)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (remove)
			execl(path, path, "-r", "openvswitch", (char *)NULL);
		else
			execl(path, path, "openvswitch", (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -ENOENT;
}

static bool openvswitch_is_loaded(void)
{
	return !access(MODULE_OPENVSWITCH, F_OK);
}

static int resolve_genl_family(const char *name)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
		char attributes[256];
	} request = { 0 };
	char response[8192];
	struct sockaddr_nl address = {
		.nl_family = AF_NETLINK,
	};
	struct nlattr *name_attr;
	struct nlmsghdr *nlh;
	ssize_t received;
	size_t name_len = strlen(name) + 1;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -errno;
	request.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	request.nlh.nlmsg_type = GENL_ID_CTRL;
	request.nlh.nlmsg_flags = NLM_F_REQUEST;
	request.nlh.nlmsg_seq = 1;
	request.genl.cmd = CTRL_CMD_GETFAMILY;
	request.genl.version = 1;
	name_attr = (struct nlattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
	name_attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	name_attr->nla_len = NLA_HDRLEN + name_len;
	memcpy((char *)name_attr + NLA_HDRLEN, name, name_len);
	request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) +
				NLA_ALIGN(name_attr->nla_len);

	if (sendto(fd, &request, request.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&address, sizeof(address)) < 0) {
		int error = -errno;
		close(fd);
		return error;
	}
	received = recv(fd, response, sizeof(response), 0);
	close(fd);
	if (received < 0)
		return -errno;

	for (nlh = (struct nlmsghdr *)response; NLMSG_OK(nlh, received);
	     nlh = NLMSG_NEXT(nlh, received)) {
		struct genlmsghdr *genl;
		struct nlattr *attr;
		int remaining;

		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *error = NLMSG_DATA(nlh);
			return error->error ? error->error : -ENOENT;
		}
		genl = NLMSG_DATA(nlh);
		remaining = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
		for (attr = (struct nlattr *)((char *)genl + GENL_HDRLEN);
		     NLA_OK(attr, remaining); attr = NLA_NEXT(attr, remaining)) {
			if ((attr->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID &&
			    attr->nla_len >= NLA_HDRLEN + sizeof(uint16_t)) {
				uint16_t family;
				memcpy(&family, (char *)attr + NLA_HDRLEN, sizeof(family));
				return family;
			}
		}
	}
	return -ENOENT;
}

static bool lsm_list_contains_bpf(void)
{
	char buffer[4096];
	ssize_t length;
	int fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return false;
	length = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (length <= 0)
		return false;
	buffer[length] = '\0';
	return strstr(buffer, "bpf") != NULL;
}

static int ensure_bpffs(void)
{
	struct statfs filesystem;

	if (mkdir("/sys/fs/bpf", 0755) && errno != EEXIST)
		return -errno;
	if (!statfs("/sys/fs/bpf", &filesystem) &&
	    (unsigned long)filesystem.f_type == BPF_FS_MAGIC)
		return 0;
	if (mount("bpffs", "/sys/fs/bpf", "bpf", 0, NULL))
		return -errno;
	return 0;
}

static int raw_bpf_obj_get(const char *path)
{
	union bpf_attr attr = { 0 };

	attr.pathname = (uint64_t)(uintptr_t)path;
	return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int raw_bpf_obj_pin(int fd, const char *path)
{
	union bpf_attr attr = { 0 };

	attr.pathname = (uint64_t)(uintptr_t)path;
	attr.bpf_fd = fd;
	return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

static int raw_bpf_link_update(int link_fd, int program_fd)
{
	union bpf_attr attr = { 0 };

	attr.link_update.link_fd = link_fd;
	attr.link_update.new_prog_fd = program_fd;
	return syscall(__NR_bpf, BPF_LINK_UPDATE, &attr, sizeof(attr));
}

static int unlink_pin_if_exists(const char *path)
{
	if (!unlink(path))
		return 0;
	return errno == ENOENT ? 0 : -errno;
}

static int replace_pinned_link(int existing_link, struct bpf_program *program,
			       struct bpf_link **link_out)
{
	struct bpf_link *link;
	int update_error;
	int pin_error;
	int unlink_error;

	if (!raw_bpf_link_update(existing_link, bpf_program__fd(program))) {
		printf("OVSwrap guard atomically replaced at %s.\n", PIN_PATH);
		return 0;
	}
	update_error = errno;
	link = bpf_program__attach_lsm(program);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "OVSwrap guard replacement failed (%s); "
			"existing pinned guard remains attached.\n",
			strerror(update_error));
		return -1;
	}
	*link_out = link;
	unlink_error = unlink_pin_if_exists(NEXT_PIN_PATH);
	if (unlink_error) {
		fprintf(stderr, "OVSwrap guard replacement failed while preparing the "
			"recovery pin (%s); existing pinned guard remains attached.\n",
			strerror(-unlink_error));
		return -1;
	}
	if (raw_bpf_obj_pin(bpf_link__fd(link), NEXT_PIN_PATH)) {
		pin_error = errno;
		fprintf(stderr, "OVSwrap guard replacement failed while creating the "
			"recovery pin (%s); existing pinned guard remains attached.\n",
			strerror(pin_error));
		return -1;
	}
	if (unlink(PIN_PATH)) {
		unlink(NEXT_PIN_PATH);
		fputs("OVSwrap guard replacement failed while opening the pin handoff; "
		      "existing pinned guard remains attached.\n", stderr);
		return -1;
	}
	if (raw_bpf_obj_pin(bpf_link__fd(link), PIN_PATH)) {
		pin_error = errno;
		if (!raw_bpf_obj_pin(existing_link, PIN_PATH))
			unlink(NEXT_PIN_PATH);
		fprintf(stderr, "OVSwrap guard replacement failed (%s); "
			"a validated guard remains attached.\n", strerror(pin_error));
		return -1;
	}
	if (unlink(NEXT_PIN_PATH))
		fprintf(stderr, "warning: redundant recovery pin remains at %s.\n",
			NEXT_PIN_PATH);
	printf("OVSwrap guard safely replaced at %s after atomic link update was "
	       "unavailable (%s).\n", PIN_PATH, strerror(update_error));
	return 0;
}

static int type_size(const struct btf *btf, const char *name)
{
	const struct btf_type *type;
	int id = btf__find_by_name_kind(btf, name, BTF_KIND_STRUCT);

	if (id < 0)
		return id;
	type = btf__type_by_id(btf, id);
	if (!type)
		return -ENOENT;
	return type->size;
}

static int require_type_size(const struct btf *btf, const char *name,
			     uint32_t minimum, uint32_t maximum,
			     uint32_t *value)
{
	int size = type_size(btf, name);

	if (size < 0) {
		fprintf(stderr, "OVSwrap guard not installed: missing BTF type "
			"struct %s.\n", name);
		return -EINVAL;
	}
	if ((uint32_t)size < minimum || (uint32_t)size > maximum ||
	    (size & 3)) {
		fprintf(stderr, "OVSwrap guard not installed: unexpected BTF size "
			"for struct %s (%d; expected %u..%u).\n",
			name, size, minimum, maximum);
		return -EINVAL;
	}
	*value = size;
	return 0;
}

static int optional_type_size(const struct btf *btf, const char *name,
			      uint32_t minimum, uint32_t maximum,
			      uint32_t *value)
{
	int size = type_size(btf, name);

	if (size < 0) {
		*value = 0;
		fprintf(stderr, "Open vSwitch BTF type struct %s is unavailable; "
			"CT actions will be conservatively denied.\n", name);
		return 0;
	}
	if ((uint32_t)size < minimum || (uint32_t)size > maximum ||
	    (size & 3)) {
		fprintf(stderr, "OVSwrap guard not installed: unexpected BTF size "
			"for struct %s (%d; expected %u..%u).\n",
			name, size, minimum, maximum);
		return -EINVAL;
	}
	*value = size;
	return 0;
}

static int load_ovs_btf(struct btf *base, struct btf **ovs_out,
			struct ovswrap_guard_config *config, const char **source_out)
{
	struct btf *ovs;

	if (!access(BTF_OPENVSWITCH, R_OK)) {
		ovs = btf__parse_split(BTF_OPENVSWITCH, base);
		if (libbpf_get_error(ovs))
			return -ENOENT;
		*source_out = BTF_OPENVSWITCH;
	} else {
		ovs = base;
		*source_out = BTF_VMLINUX;
	}

	if (optional_type_size(ovs, "ovs_conntrack_info", 32, 4096,
			       &config->conntrack_info_size) ||
	    require_type_size(ovs, "sample_arg", 8, 8,
			      &config->sample_arg_size) ||
	    require_type_size(ovs, "check_pkt_len_arg", 4, 4,
			      &config->check_pkt_len_arg_size) ||
	    require_type_size(ovs, "ovs_tunnel_info", sizeof(uint32_t),
			      sizeof(uint64_t),
			      &config->tunnel_info_size)) {
		if (ovs != base)
			btf__free(ovs);
		return -EINVAL;
	}
	*ovs_out = ovs;
	return 0;
}

int main(int argc, char **argv)
{
	const char *object_path = argc == 2 ? argv[1] : DEFAULT_OBJECT_PATH;
	const char *btf_source = NULL;
	struct ovswrap_guard_config config = { 0 };
	struct bpf_object *object = NULL;
	struct bpf_program *program;
	struct bpf_map *config_map;
	struct bpf_link *link = NULL;
	struct btf *base_btf = NULL;
	struct btf *ovs_btf = NULL;
	char modprobe_path[PATH_MAX] = "";
	uint32_t key = 0;
	bool guard_attached = false;
	bool ovs_loaded_by_loader = false;
	bool ovs_was_loaded;
	int btf_error;
	int existing_link = -1;
	int error = 1;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [ovswrap_guard.bpf.o]\n", argv[0]);
		return 2;
	}
	if (geteuid()) {
		fputs("OVSwrap guard not installed: loader must run as root.\n", stderr);
		return 1;
	}
	if (!lsm_list_contains_bpf()) {
		fputs("OVSwrap guard not installed: BPF LSM is not active.\n"
		      "Enable bpf in the kernel LSM list, reboot, then retry.\n", stderr);
		goto out;
	}
	base_btf = btf__parse(BTF_VMLINUX, NULL);
	if (libbpf_get_error(base_btf)) {
		base_btf = NULL;
		btf_unavailable();
		goto out;
	}

	object = bpf_object__open_file(object_path, NULL);
	if (libbpf_get_error(object)) {
		object = NULL;
		fprintf(stderr, "OVSwrap guard not installed: cannot open %s.\n", object_path);
		goto out;
	}
	if (bpf_object__load(object)) {
		fputs("OVSwrap guard not installed: BPF object failed verification/load.\n",
		      stderr);
		goto out;
	}
	config_map = bpf_object__find_map_by_name(object, "config_map");
	program = bpf_object__find_program_by_name(object, "ovswrap_netlink_send");
	if (!config_map || !program) {
		fputs("OVSwrap guard not installed: BPF object is missing required members.\n",
		      stderr);
		goto out;
	}
	if (ensure_bpffs()) {
		fputs("OVSwrap guard not installed: bpffs is unavailable.\n", stderr);
		goto out;
	}
	existing_link = raw_bpf_obj_get(PIN_PATH);
	if (existing_link < 0 && errno != ENOENT) {
		fputs("OVSwrap guard not installed: existing pin could not be opened.\n",
		      stderr);
		goto out;
	}

	ovs_was_loaded = openvswitch_is_loaded();
	if (!ovs_was_loaded) {
		int modprobe_error =
			read_modprobe_path(modprobe_path, sizeof(modprobe_path));

		if (modprobe_error) {
			fprintf(stderr,
				"OVSwrap guard not installed: %s does not provide an "
				"executable absolute modprobe path (%s).\n"
				"Edit ovswrap_guard.c to use this system's correct "
				"absolute modprobe path, rebuild, and retry.\n",
				MODPROBE_PATH_FILE, strerror(-modprobe_error));
			goto out;
		}
		if (run_modprobe(modprobe_path, false)) {
			ovs_loaded_by_loader = openvswitch_is_loaded();
			fputs("OVSwrap guard not installed: could not load or "
			      "resolve Open vSwitch.\n", stderr);
			goto out;
		}
		ovs_loaded_by_loader = openvswitch_is_loaded();
	}
	config.flow_family = resolve_genl_family("ovs_flow");
	config.packet_family = resolve_genl_family("ovs_packet");
	if ((int32_t)config.flow_family < 0 || (int32_t)config.packet_family < 0) {
		fputs("OVSwrap guard not installed: Open vSwitch Generic Netlink families are unavailable.\n",
		      stderr);
		goto out;
	}
	btf_error = load_ovs_btf(base_btf, &ovs_btf, &config, &btf_source);
	if (btf_error) {
		if (btf_error == -ENOENT)
			btf_unavailable();
		goto out;
	}
	if (bpf_map_update_elem(bpf_map__fd(config_map), &key, &config, BPF_ANY)) {
		fputs("OVSwrap guard not installed: could not configure BPF maps.\n", stderr);
		goto out;
	}

	if (existing_link >= 0) {
		if (replace_pinned_link(existing_link, program, &link))
			goto out;
	} else {
		link = bpf_program__attach_lsm(program);
		if (libbpf_get_error(link)) {
			link = NULL;
			fputs("OVSwrap guard not installed: BPF LSM attach failed.\n", stderr);
			goto out;
		}
		if (bpf_link__pin(link, PIN_PATH)) {
			fputs("OVSwrap guard not installed: pin failed; new link was detached.\n",
			      stderr);
			goto out;
		}
		printf("OVSwrap guard installed and pinned at %s.\n", PIN_PATH);
	}
	guard_attached = true;

	printf("Open vSwitch BTF source: %s\n", btf_source);
	if (ovs_was_loaded)
		puts("modprobe path: not used (Open vSwitch was already loaded)");
	else
		printf("modprobe path: %s\n", modprobe_path);
	printf("Generic Netlink families: ovs_flow=%u ovs_packet=%u\n",
	       config.flow_family, config.packet_family);
	printf("Verified type sizes: ovs_conntrack_info=%u sample_arg=%u "
	       "check_pkt_len_arg=%u ovs_tunnel_info=%u\n",
	       config.conntrack_info_size, config.sample_arg_size,
	       config.check_pkt_len_arg_size, config.tunnel_info_size);
	error = 0;

out:
	if (existing_link >= 0)
		close(existing_link);
	if (link)
		bpf_link__destroy(link);
	if (object)
		bpf_object__close(object);
	if (ovs_btf && ovs_btf != base_btf)
		btf__free(ovs_btf);
	btf__free(base_btf);
	if (ovs_loaded_by_loader && !guard_attached) {
		if (run_modprobe(modprobe_path, true))
			fputs("warning: Open vSwitch was loaded by this failed "
			      "installation and could not be unloaded; no new guard "
			      "was attached.\n", stderr);
		else
			fputs("Open vSwitch was unloaded after guard installation "
			      "failed.\n", stderr);
	}
	return error;
}
