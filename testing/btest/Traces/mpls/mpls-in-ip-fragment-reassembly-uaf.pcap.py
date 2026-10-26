#!/usr/bin/env python3
"""Fragmented MPLS-in-IP traffic exposing the same reassembly lifetime UAF as skip.

This is the MPLS structural twin of ipv4/skip-fragment-reassembly-uaf.pcap. Like
the skip analyzer, the MPLS analyzer forwards the *same* packet into its default
child (IP) after stripping the label stack, so when it sits under an IP protocol
number it re-parses an already-reassembled packet and overwrites the sole owner
of the reassembled buffer.

Two IPv4 fragments (outer proto 137, MPLS-in-IP per RFC 4023) reassemble into a
datagram consisting of a single bottom-of-stack MPLS label followed by an inner
IPv4/UDP packet whose total-length field is deliberately zero. The inner IP
header straddles the fragment boundary (offset 8, frag=1), so the header the
MPLS path forwards into only exists in the reassembled buffer.

This is an intentionally malformed reproducer: the inner IP total length of 0 is
the point, so dissector complaints about the reassembled payload are expected.
The two outer fragments themselves are well formed.

MPLS-in-IP is not wired up by default in Zeek (MPLS is only a child of the
0x8847 ethertype and PPP 0x0281); the accompanying btest registers MPLS under
IP proto 137 explicitly, mirroring how the skip test registers skip under 253.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to build packets with
Scapy's high-level API. Human review is required before submission.
"""

from pathlib import Path

from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUTER_SRC_IP = "192.168.0.1"
OUTER_DST_IP = "192.168.0.2"
INNER_SRC_IP = "10.0.0.1"
INNER_DST_IP = "10.0.0.2"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"

# MPLS-in-IP (RFC 4023) carried by the outer (fragmented) datagram.
OUTER_PROTO = 137
OUTER_IP_ID = 7

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
    """One outer proto-137 fragment carrying a raw slice of the reassembled buffer."""
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
    # A single bottom-of-stack MPLS label the MPLS path strips before forwarding
    # the remainder (the inner IP packet) into IP.
    mpls_label = bytes(MPLS(label=0, cos=0, s=1, ttl=64))
    reassembled = mpls_label + inner_packet()
    # Split so the inner IP header straddles the boundary at offset 8 (frag=1):
    # the 4-byte label plus the first 4 inner-header bytes sit in fragment one.
    packets = [
        outer_fragment(reassembled[:8], flags="MF", frag=0),
        outer_fragment(reassembled[8:], flags=0, frag=1),
    ]

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
