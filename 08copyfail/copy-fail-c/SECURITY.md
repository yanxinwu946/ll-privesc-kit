# Security Policy

This repository ships a working CVE-2026-31431 exploit and a non-destructive
vulnerability checker. The kernel bug itself is previously disclosed and
tracked; this policy covers bugs in *this repository's code* (the dropper,
the payload, the checker, the shared primitive).

## Reporting a Vulnerability

If you discover a bug here that has security-relevant consequences (e.g., the
`vulnerable` checker reports `vulnerable` on a kernel that is actually patched
or vice versa; the dropper damages on-disk state; the payload behaves
unexpectedly under restricted environments), please report it through
GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/tgies/copy-fail-c/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill out the form with:
   - Description of the issue
   - Steps to reproduce (kernel version, distro, arch)
   - Potential impact
   - Any suggested fixes (optional)

For the underlying kernel vulnerability (CVE-2026-31431) itself, report to the
upstream Linux kernel security team and the affected distro security teams,
not here. The canonical writeup is at [copy.fail](https://copy.fail/).

### What to Expect

- Confirmation that your report was received
- Regular updates on the fix progress
- Credit in the resulting commit or release notes (unless you prefer to remain anonymous)

## Maintainer

- **GPG Fingerprint:** `31B0 0A90 B561 D52E 0CC6  3E36 F489 74F8 53E3 65D2`
- **Public Key:** [github.com/tgies.gpg](https://github.com/tgies.gpg)
