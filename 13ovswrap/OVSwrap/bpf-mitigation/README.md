# OVSwrap BPF mitigation

This is a temporary mitigation for systems that cannot yet install the kernel
fix. `ovswrap_guard.bpf.c` contains the BPF program; `ovswrap_guard.c` builds
the userspace loader.

The BPF program runs at `lsm/netlink_send`. It immediately allows
non-Generic-Netlink traffic, then examines only Open vSwitch flow `NEW`/`SET`
and packet `EXECUTE` requests. For their action lists it reproduces the patched
kernel's generated-action length accounting, including CT expansion, SET
conversion, and nested `CLONE`, `SAMPLE`, `DEC_TTL`, and `CHECK_PKT_LEN`
actions. It returns `EMSGSIZE` if any generated nested attribute would exceed
the 65,535-byte `nla_len` limit. Safe large lists are allowed; the entire valid
65,528-byte aligned action payload is covered.

The parser uses the kernel-enforced action nesting limit of 16. Its
state-machine and callback-iterator design deliberately avoids verifier-hostile
large loops so it loads on stricter older verifiers, including affected
enterprise 5.14 kernels. The iterator has 524,593 transitions, enough for
sixteen maximum-size action lists plus their message and attribute parsing. A
relevant OVS request fails closed if it is malformed, has more than 16
top-level command attributes, or exhausts that total budget. Current OVS flow
and packet commands define at most 11 distinct top-level attributes. Unrelated
Netlink protocols are not parsed, and unrelated Generic-Netlink batches are
allowed within the total transition budget.

The guard is fail-closed and deliberately permits large valid batches; a
malicious sender can therefore force substantial parser work, making this an
availability tradeoff of the temporary mitigation.

The loader:

- verifies that BPF LSM and vmlinux BTF are available;
- if OVS is not already loaded, requires `/proc/sys/kernel/modprobe` to name an executable absolute module helper;
- opens and verifier-loads the BPF object before loading Open vSwitch;
- loads OVS only when needed and only after those preflight checks;
- resolves the live `ovs_flow` and `ovs_packet` family IDs;
- derives the generated CT, SAMPLE, CHECK_PKT_LEN, and tunnel-action sizes from OVS BTF; if the CT type is absent, CT actions are denied while the remaining mitigation stays active;
- configures the map before attaching the LSM program; and
- attempts to unload OVS if it loaded the module and a later pre-attachment step fails.

Loading OVS and attaching the initial guard are not atomic; install it before
admitting untrusted local users or workloads, or temporarily quiesce them
during installation.

## Build and install

Build requirements are clang, libbpf development headers, libelf, zlib, and
pkg-config. The Makefile uses both the compiler and linker flags published by
libbpf's pkg-config file. Runtime requires root, an active BPF LSM, vmlinux
BTF, and OVS BTF (`/sys/kernel/btf/openvswitch` for modular OVS or the required
types in vmlinux for built-in OVS).

```sh
make
sudo make install
sudo /usr/sbin/ovswrap_guard
```

The loader prints whether modprobe was needed, the selected path when used, the
BTF source, family IDs, and derived sizes. Any missing prerequisite, verifier
failure, required BTF mismatch, or attach failure produces an explicit error
and a nonzero exit status. If OVS needs loading and `/proc/sys/kernel/modprobe`
is unusable, the loader short-circuits with an error.

The pinned link is `/sys/fs/bpf/ovswrap_guard`. To detach it:

```sh
sudo rm -f /sys/fs/bpf/ovswrap_guard /sys/fs/bpf/ovswrap_guard_next
```

The pin survives loader exit but not reboot. Rerun the loader after reboot and
after any OVS module unload/reload so it can resolve the current family IDs and
BTF.

## Warning

The mitigation was verified on a handful of distros with success; it is possible
you may need to tweak, e.g., the build instructions, and a detail here or
there, depending on the target distro. Use the existing implementation as a
starting point and adjust for your target if necessary.