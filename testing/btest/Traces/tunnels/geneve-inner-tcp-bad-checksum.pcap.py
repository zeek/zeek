#!/usr/bin/env python3
"""
Generate geneve-inner-tcp-bad-checksum.pcap: a single Geneve packet whose
inner Ethernet/IP/TCP SYN has a deliberately wrong TCP checksum.

Adapted with Claude Sonnet 5.5 (Anthropic) to be reproducible.
"""

from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, wrpcap
from scapy.contrib.geneve import GENEVE

GENEVE_PORT = 6081

BASE_TIME = 1_700_000_000.0


def main():
    inner = (
        Ether(dst="aa:bb:cc:dd:ee:02", src="aa:bb:cc:dd:ee:01")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="S", chksum=0xDEAD)
    )

    pkt = (
        Ether(dst="de:ad:be:ef:00:02", src="de:ad:be:ef:00:01")
        / IP(src="192.168.1.1", dst="192.168.1.2")
        / UDP(sport=23456, dport=GENEVE_PORT)
        / GENEVE(vni=42, proto=0x6558)
        / inner
    )

    pkt.time = BASE_TIME

    wrpcap(str(Path(__file__).with_suffix("")), [pkt])


if __name__ == "__main__":
    main()
