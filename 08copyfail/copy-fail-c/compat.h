/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail -- CVE-2026-31431
 * UAPI compatibility shim for pre-5.6 linux-libc-dev header sets.
 *
 * __kernel_old_time_t and struct __kernel_old_timespec entered the kernel
 * UAPI headers in Linux 5.6 (2020); the vendored nolibc uses both. Building
 * the payload against an older header set fails to find them. This header is
 * force-included ahead of nolibc (see the payload target in the Makefile) so
 * such builds get the same definitions a 5.6+ header provides. The typedef
 * and struct mirror the upstream UAPI definitions byte-for-byte, so the
 * time64 size assertions in nolibc/time.h hold identically. See issue #14.
 *
 * On 5.6+ header sets the version guard is false and this header defines
 * nothing.
 */
#ifndef COPY_FAIL_COMPAT_H
#define COPY_FAIL_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#include <linux/posix_types.h>

typedef __kernel_long_t __kernel_old_time_t;

struct __kernel_old_timespec {
    __kernel_old_time_t tv_sec;
    long                tv_nsec;
};
#endif

#endif /* COPY_FAIL_COMPAT_H */
