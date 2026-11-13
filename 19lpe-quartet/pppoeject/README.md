# PPPoEject (CVE-2026-68121)

[Writeup](https://heyitsas.im/posts/lpe-quartet/)

> [!WARNING]
> The PoC is provided solely to help defenders, maintainers, and authorized
> security teams validate patches, mitigations, detections, and exposure on
> systems they own or are explicitly authorized to test.
>
> You are solely responsible for ensuring that your use of this material is
> lawful, authorized, controlled, and conducted in an isolated test environment.


> [!WARNING]
> **This PoC is destructive.** It deliberately corrupts live kernel memory.
> A misplaced overwrite can corrupt unrelated kernel memory and hang/crash the machine.
>
> Run only in a disposable VM/throwaway host.

The PoC:

1. Compiles embedded helpers and locates the randomized kernel text base with an
x86-64 prefetch/RDTSCP timing side channel
2. builds an AF_PACKET TX-ring carrier containing fake `struct file` objects and
grooms a populated fdtable into the target allocation
3. stalls a PPPoE payload copy on an attacker-owned FUSE page, then adds IP6GRE
to an empty team device on Fedora or through a bonding chain on Ubuntu
4. makes `dev_hard_header()` reallocate the skb head, then uses the stale PPPoE
header pointer to redirect an fdtable entry to the fake file, and
5. closes the redirected descriptor, executes the controlled callback, installs
root credentials, and opens `/bin/sh -p`.

The PoC assumes and targets x86-64 to keep things simple. In theory, the bug
should not be arch-specific, but you'd need to port a lot (from leaking the
kernel base to the rest of the chain).

## Requirements

Enumerating exhaustively for completeness:

- At least 4 available CPUs (important for the PPPoE sender, fdtable
  reclaimer/carrier, FUSE blocker, and trigger/release orchestrator workers to
  perform timing-critical work with less scheduler interference)
- Fedora 44 with `6.19.10-300.fc44.x86_64`, or Ubuntu 24.04 with
  `6.8.0-124-generic` or `6.8.0-136-generic` (you can try removing these
  checks, but other distros/kernel versions may require per-target
  customization/grooming)
- An ordinary non-root account with a `passwd` entry and a home directory it
  owns
- An Intel or AMD x86-64 CPU with RDTSCP, KPTI/PTI inactive, and at least four
  logical CPUs in the process affinity mask
- Unprivileged user/network namespace creation with `CAP_NET_ADMIN` and
  `CAP_NET_RAW` inside that namespace
- Read/write access to `/dev/fuse`, plus FUSE, PPPoE, IP6GRE, AF_PACKET/TX-ring,
  and team support on Fedora or bonding support on Ubuntu
- Private expedited `membarrier` for selected low-order layouts
- Dummy and 802.1Q VLAN devices for selected high-order layouts
- An `RLIMIT_NOFILE` hard limit large enough for the selected carrier geometry,
  checked at runtime and potentially requiring up to 8,192 descriptors
- Misc. userspace things (which the tested distros in scope should mostly have
  by default): Python 3.10+, `gcc` with libc and Linux UAPI development
  headers, `taskset`, `unshare`, `ip`, `true`, and `/bin/sh`, plus `aa-exec`
  and the loaded `trinity` profile on Ubuntu if direct `unshare -Urn` is
  denied

Tested only with 4GB RAM and a variety of 4+ CPU counts. Other CPU/memory combos
may need more grooming and/or may redirect the write into unrelated memory.

Run it as an unprivileged user with a `passwd` entry. The Ubuntu conversion can
take a while (e.g., 300+ attempts).

## Usage

```sh
python3 pppoeject_root_repro.py
```