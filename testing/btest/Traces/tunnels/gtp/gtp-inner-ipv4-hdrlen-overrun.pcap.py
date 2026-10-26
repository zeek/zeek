#!/usr/bin/env python3
"""Generate a GTPv1 G-PDU with an invalid inner IPv4 header length.

The inner IPv4 packet declares ihl=15 (60 bytes) while its total length is
20 bytes, leaving no in-bounds transport header for pkt_hdr event generation.

Written with OpenAI Codex using Scapy.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap
from scapy.contrib.gtp import GTPHeader

BASE_TIME = 1_700_000_000.0


def build_packets():
    inner = bytes(
        IP(
            src="10.0.0.1",
            dst="10.0.0.2",
            ihl=15,
            len=20,
            id=0x1234,
            ttl=64,
            proto=6,
            chksum=0,
        )
    )

    packet = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="192.168.1.1", dst="192.168.1.2")
        / UDP(sport=2152, dport=2152)
        / GTPHeader(gtp_type=255, teid=1)
        / Raw(inner)
    )

    return [packet]


def main():
    packets = build_packets()

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
