#!/usr/bin/env python3

"""
Generate the truncated IPv4/TCP pcapng used for the IP discarder crash path.

The packet's wire length is Ethernet + IPv4 + TCP (54 bytes), but the capture
contains only Ethernet + IPv4 (34 bytes).  This lets Zeek see an IP total length
that includes a TCP header while the captured data stops at the IP payload.
"""

from pathlib import Path

from scapy.all import wrpcapng
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

TIMESTAMP = 0.000001


def main() -> None:
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", id=0x1001, ttl=64)
        / TCP(sport=12345, dport=80, flags="S", window=8192)
    )

    full_packet = bytes(pkt)
    captured_packet = full_packet[: len(Ether() / IP())]

    assert len(full_packet) == 54
    assert len(captured_packet) == 34

    # Re-dissect only the captured bytes; wirelen records the original size.
    truncated = Ether(captured_packet)
    truncated.time = TIMESTAMP
    truncated.wirelen = len(full_packet)

    wrpcapng(str(Path(__file__).with_suffix("")), [truncated])


if __name__ == "__main__":
    main()
