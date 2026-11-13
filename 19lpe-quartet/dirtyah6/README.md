# DirtyAH6 (CVE-2026-80844)

[Writeup](https://heyitsas.im/posts/lpe-quartet/)

> [!WARNING]
> The PoC is provided solely to help defenders, maintainers, and authorized
> security teams validate patches, mitigations, detections, and exposure on
> systems they own or are explicitly authorized to test.
>
> You are solely responsible for ensuring that your use of this material is
> lawful, authorized, controlled, and conducted in an isolated test environment.


> [!WARNING]
> **This PoC is destructive.** It modifies `/etc/pam.d/su` without any rollback.
> A misplaced overwrite can corrupt unrelated kernel memory and hang/crash the
> machine.
>
> Run only in a disposable VM/throwaway host.


The PoC:

1. enters a private user/network namespace, builds veth, IOAM6, netem, AH6, and
ESP-in-UDP paths and queues file-backed ESP skbs sourced from `/etc/pam.d/su`

2. sends a malformed IPv6 routing header whose `segments_left` exceeds its
address count, making AH6 corrupt a nearby target skb

3. uses the corrupted skb metadata to make ESP decrypt chosen bytes into the
file-backed PAM page, and

4. runs `su - root` after `pam_rootok.so` has become `pam_permit.so`.

The PoC assumes and targets x86-64 to keep things simple. In theory, the bug
should not be arch-specific.

## Requirements

Enumerating exhaustively for completeness:

- Fedora 43 with `7.1.3-100.fc43.x86_64`, or Ubuntu 24.04 with `6.8.0-134-generic` (you can try removing these checks, but other distros/kernel versions may require per-target customization/grooming)
- An ordinary non-root account and the expected, unmodified `/etc/pam.d/su` layout
- Unprivileged user/network namespace creation with `CAP_NET_ADMIN` and `CAP_NET_RAW` inside that namespace
- Kernel support for IPv6 AH/XFRM with HMAC-SHA256, AES-CBC ESP-in-UDP, IOAM6 LWT, `sch_netem`, and veth
- Misc. userspace things (which the tested distros in scope should mostly have by default): Python 3.10+, `gcc`, `openssl`, `ip`, `tc`, `unshare`, `nsenter`, `su`, `bash`, `env`, `sh`, `sleep`, `awk`, `seq`, `grep`, `kill`, `cat`, `sed`, `rm`, `dd`, `od`, and `tr`, plus `aa-exec` and the loaded `trinity` profile if direct `unshare -Urn` is denied

Fedora tested best with 16 vCPUs/32 GB RAM; Ubuntu with 29 vCPUs/8 GB RAM -- other combos might work (especially different vCPU counts). The PoC performs _reasonably_ with a range of other vCPU/RAM combos, but YMMV.

Run it as an unprivileged user with a `passwd` entry.

## Usage

```sh
python3 dirtyah6_root_repro.py
```
