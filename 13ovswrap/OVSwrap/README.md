# OVSwrap (CVE-2026-64531)

[Writeup](https://heyitsas.im/posts/ovswrap)

> [!WARNING]
> The PoC is provided solely to help defenders, maintainers, and authorized
> security teams validate patches, mitigations, detections, and exposure on
> systems they own or are explicitly authorized to test.
>
> You are solely responsible for ensuring that your use of this material is
> lawful, authorized, controlled, and conducted in an isolated test environment.


> [!WARNING]
> **This PoC is destructive.** On success it corrupts a live kernel credential,
> modifies `/etc/sudoers.d` or `/etc/sudoers`, opens a root shell, and leaves
> detached processes and corrupted OVS state alive to avoid unsafe teardown.
>
> Run it only in a disposable VM/throwaway host. Rebooting stops the remaining
> processes but does not undo the sudoers modification.

The PoC:

1. forks a host-side writer process, then creates a private user/network namespace and OVS datapath
2. wraps a generated nested-action `nla_len`
3. uses fake OVS actions for a kernel-pointer leak, kernel read, and targeted 32-bit decrement
4. finds the writer process in kernel memory and corrupts its credential, and
5. signals it to write a passwordless sudo rule, then launches `sudo -n bash`.

The PoC assumes and targets x86-64 to keep things simple. In theory, the bug should not be arch-specific.

## Requirements

- Linux x86-64 running an affected, unfixed kernel
- Open vSwitch kernel datapath support, built in or loadable
- OVS conntrack, conntrack labels, and the FTP conntrack helper
- Unprivileged user and network namespace creation (`unshare -Urn`)
- Module loading permitted if the required modules are not already loaded
- Python 3.7+
- `sudo`, `bash`, `unshare`, and `id`
- 2 GiB+ RAM recommended

Run it as an unprivileged user with a `passwd` entry.

## Usage

```sh
python3 ovswrap-poc.py
```

The PoC will automatically try `unshare -Urn` and fall back on `aa-exec -p trinity -- unshare -Urn` if it's AppArmor-blocked.

## Kernel-build data

The PoC contains pre-derived values for **~800 exact x86-64 kernel builds**,
matched using:

```text
uname -r
uname -v
uname -m
```

A matching record needs no local symbols, BTF, debug package, or `pahole`. For a non-covered build, the PoC asks for confirmation and attempts dynamic
derivation from:

- `System.map` or nonzero `/proc/kallsyms`;
- kernel/module BTF or matching unstripped kernel objects; and
- `pahole`, which **must already be installed**.

Failure to derive values does **not** mean the kernel is unaffected, as dynamic derivation can fail for a number of reasons; see the [writeup](https://heyitsas.im/posts/ovswrap#are-you-affected--mitigation) for better ways to tell if you are affected.
