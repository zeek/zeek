#!/usr/bin/env python3

"""Generate unicast UDP traffic to the mDNS and LLMNR service ports."""

import socket
import struct
import sys


def packet(dst_port: int, timestamp: int) -> bytes:
    """Build one Ethernet/IPv4/UDP packet with a non-DNS opcode."""
    src_mac = bytes.fromhex("020000000001")
    dst_mac = bytes.fromhex("020000000002")
    ethernet = dst_mac + src_mac + struct.pack("!H", 0x0800)

    src_ip = socket.inet_aton("192.0.2.10")
    dst_ip = socket.inet_aton("192.0.2.20")

    dns_header = struct.pack("!HHHHHH", 0, 0x7800, 0, 0, 0, 0)
    udp_length = 8 + len(dns_header)
    udp = struct.pack("!HHHH", 40000, dst_port, udp_length, 0) + dns_header

    total_length = 20 + len(udp)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        src_ip,
        dst_ip,
    )

    frame = ethernet + ipv4 + udp
    record = struct.pack("<IIII", timestamp, 0, len(frame), len(frame))
    return record + frame


def main() -> None:
    output = sys.argv[1]
    pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    with open(output, "wb") as pcap_file:
        pcap_file.write(pcap_header)
        pcap_file.write(packet(5353, 1))
        pcap_file.write(packet(5355, 2))


if __name__ == "__main__":
    main()
