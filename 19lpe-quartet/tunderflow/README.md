# TUNderflow (CVE-2026-81000)

[Writeup](https://heyitsas.im/posts/lpe-quartet/)

> [!WARNING]
> The PoC is provided solely to help defenders, maintainers, and authorized
> security teams validate patches, mitigations, detections, and exposure on
> systems they own or are explicitly authorized to test.
>
> You are solely responsible for ensuring that your use of this material is
> lawful, authorized, controlled, and conducted in an isolated test environment.


> [!WARNING]
> **This PoC is destructive.** It modifies `/etc/pam.d/su` without any
> rollback.
> A misplaced overwrite can corrupt unrelated kernel memory and hang/crash the
> machine.
>
> Run only in a disposable VM/throwaway host.

The PoC:

1. enters a private user/network namespace, creates TUN devices and an
OVS/netkit/VXLAN setup that propagates oversized receive headroom
2. grooms 4 KiB skb heads beside pipe rings containing a one-byte file-backed
buffer from `/etc/pam.d/su`
3. sends candidate TUN packets whose out-of-bounds OVS write can set
`PIPE_BUF_FLAG_CAN_MERGE` in a nearby `pipe_buffer`, and
4. writes `pam_permit.so` through the pipe, finishing off with `su - root`.

The PoC assumes and targets x86-64 to keep things simple. In theory, the bug
should not be arch-specific.

## Requirements

Enumerating exhaustively for completeness:

- Fedora 44 Server with `6.19.10-300.fc44.x86_64`, or Ubuntu 24.04.4 with
  `6.17.0-40-generic` (you can try removing these checks, but other
  distros/kernel versions may require per-target customization/grooming)
- An ordinary non-root account, an unmodified `/etc/pam.d/su` containing
  `pam_rootok.so`, and the `pam_rootok.so` and `pam_permit.so` PAM modules
- Logical CPU 0 in the process affinity mask
- Unprivileged user/network namespace creation with `CAP_NET_ADMIN` inside that
  namespace
- An accessible `/dev/net/tun`, plus TUN, Open vSwitch datapath, netkit, and
  VXLAN kernel support
- Permission to create 256 KiB pipe rings and capacity for roughly 800 open file
  descriptors
- Misc. userspace things (which the tested distros in scope should mostly have
  by default): Python 3.10+, `ip`, `unshare`, `true`, and `su`, plus `aa-exec`
  and the loaded `trinity` profile on Ubuntu if direct `unshare -Urn` is
  denied

Both targets were tested with 29 vCPUs at 4 GB and 32 GB RAM, with the latter
more reliable. Other CPU/memory combos may need more grooming and may redirect
the overwrite into unrelated memory.

Run it as an unprivileged user with a `passwd` entry.

## Usage

```sh
python3 tunderflow_root_repro.py
```