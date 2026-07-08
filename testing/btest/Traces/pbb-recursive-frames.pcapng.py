#!/usr/bin/env python3

"""
Generates a packet capture with a long packet analyzer chain.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcapng

DEPTH = 50
OUT = Path(__file__).with_suffix("")


inner = bytes(
    Ether(dst="02:00:00:00:10:02", src="02:00:00:00:10:01", type=0x0800)
    / IP(src="192.0.2.1", dst="198.51.100.1")
    / UDP(sport=12345, dport=53)
    / Raw(b"X")
)

for _ in range(DEPTH):
    inner = bytes(
        Ether(dst="02:00:00:00:20:02", src="02:00:00:00:20:01", type=0x88E7)
        / Raw(b"\x00\x00\x00\x01" + inner)
    )

pkt = Ether(inner)
pkt.time = 1700000000.0

wrpcapng(str(OUT), [pkt])
