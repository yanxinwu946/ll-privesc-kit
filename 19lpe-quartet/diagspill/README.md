# DiagSpill (CVE-2026-74469)

[Writeup](https://heyitsas.im/posts/lpe-quartet/)

> [!WARNING]
> The PoC is provided solely to help defenders, maintainers, and authorized
> security teams validate patches, mitigations, detections, and exposure on
> systems they own or are explicitly authorized to test.
>
> You are solely responsible for ensuring that your use of this material is
> lawful, authorized, controlled, and conducted in an isolated test environment.


> [!WARNING]
> **This PoC is destructive.** It overwrites roughly 8 MiB of kernel memory and
> leaves corrupted page tables held by the `diagspill_hold` sacrificial-memory
> holder until reboot. Killing that process can destabilize the kernel.
>
> Unrelated memory may be corrupted and the machine may panic. Run only in a
> disposable VM/throwaway host.

The PoC:

1. compiles the embedded C exploit (which does the below)
2. places SCTP diagnostic-reply skbs beside a large page-table reservoir and
starts 2,048 credential-worker processes
3. creates an SCTP association with 81,920 peer transports, whose 16-bit count
is 16,384, then asks sock_diag for a reply sized for 16,384 peers while the
copy loop writes all 81,920
4. turns overwritten PMD entries into user-readable and user-writable mappings
of physical RAM, then scans them for the workers' live credentials, and
5. zeros a worker's UID/GID fields, uses that worker to install a temporary
sudoers rule, opens a root shell through `sudo`, and detaches the process
holding the corrupted mappings.

The PoC assumes and targets x86-64 to keep things simple. In theory, the bug
should not be arch-specific.

## Requirements

Enumerating exhaustively for completeness:

- Ubuntu 24.04 with `6.17.0-35-generic`, or Fedora 44 with
  `6.19.10-300.fc44.x86_64` (you can try removing these checks, but other
  distros/kernel versions may require per-target customization/grooming)
- x86-64 with 4 KiB pages, exactly four online logical CPUs, CPUs 0-3 in the
  process affinity mask, and `MemTotal` between 3,700,000 and 4,200,000 KiB
- An ordinary account whose real, effective, and saved UID/GID values match
- An account name containing only letters, digits, `_`, or `-`
- No pre-existing read access to `/root` or passwordless sudo
- SCTP and `sctp_diag` kernel support, transparent huge-page allocation, enough
  process/file limits for 2,048 workers and the diagnostic socket wall, and
  enough x86-64 address space and memory to retain about 2,343 MiB of page
  tables on Ubuntu or 3,125 MiB on Fedora
- A working `/etc/sudoers.d` include and an executable `/usr/bin/sudo`
- Misc. userspace things (which the tested distros in scope should mostly have
  by default): Python 3.9+, `/usr/bin/env`, `cc` with libc and Linux UAPI
  development headers, `id`, `sudo`, `true`, `sh`, and `rm`

The PoC is very vCPU-count-/RAM-sensitive, so it enforces 4 vCPUs and 4 GB RAM.
You will likely need per-target customization/grooming for other vCPU/memory
combos.

Run it as an unprivileged user with a `passwd` entry; the PoC can take a bit of
time to build the large SCTP association.

## Usage

```sh
python3 diagspill_root_repro.py
```

After a run (successful or not), reboot the machine to release
`diagspill_hold`to be safe. If you kill it directly, you will almost certainly
destabilize the kernel.