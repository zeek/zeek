#!/usr/bin/env python3
"""Generate udp-contents-truncated-oob.pcap: a truncated UDP capture that
triggers an out-of-bounds content read.

The IPv4 header declares a full 65535-byte total length, and the UDP header
declares the matching payload length, but no UDP payload bytes are actually
captured. UDPAnalyzer::DeliverPacket used the IP-declared payload length
without bounding it by the captured bytes remaining, so enabling udp_contents
caused a heap out-of-bounds read of ~65507 bytes. The record's on-wire length
is set to the declared size while its captured length stays at the headers
only, reproducing the truncation.

Generated with Claude Opus 4.8.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import IP, UDP, Ether, wrpcap

IP_HEADER_LENGTH = 20
UDP_HEADER_LENGTH = 8


def build_packet(ip_total_length: int):
    """Build an Ethernet/IPv4/UDP header with no captured UDP payload."""
    udp_length = ip_total_length - IP_HEADER_LENGTH

    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(
            src="192.0.2.1",
            dst="198.51.100.2",
            id=0x1234,
            ttl=64,
            len=ip_total_length,
        )
        / UDP(sport=40000, dport=55555, len=udp_length, chksum=0)
    )

    # Deterministic timestamp so the capture is byte-for-byte reproducible.
    pkt.time = 0
    # Declare the full on-wire length while only the headers are captured,
    # marking the packet as truncated.
    pkt.wirelen = 14 + ip_total_length
    return pkt


def main() -> int:
    default_output = Path(__file__).with_suffix("")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_output,
        help="output pcap path (default: %(default)s)",
    )
    parser.add_argument(
        "--ip-total-length",
        type=int,
        default=65535,
        help="IPv4 total length to declare (default: %(default)s)",
    )
    args = parser.parse_args()

    pkt = build_packet(args.ip_total_length)
    wrpcap(str(args.output), pkt)
    print(f"Wrote 1 packet to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
