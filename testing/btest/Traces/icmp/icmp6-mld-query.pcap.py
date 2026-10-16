#!/usr/bin/env python3
"""
Generate an IPv6 Multicast Listener Discovery (MLD) Query packet using scapy.
MLD uses ICMPv6 type 130 for Multicast Listener Query. The packet carries a
Hop-by-Hop Router Alert option (RFC 2711) as MLD requires, and is written as a
raw-IPv6 pcap (no link layer) beside this script.

Generated with Claude Sonnet 4.6 (Anthropic), adapted with Claude Sonnet 5.5
(Anthropic) to use a fixed source address and timestamp so the trace is
reproducible.
"""

from pathlib import Path

from scapy.all import (
    ICMPv6MLQuery,
    IPv6,
    IPv6ExtHdrHopByHop,
    RouterAlert,
    wrpcap,
)

# Fixed source address; the all-nodes multicast group is the destination.
# The address is hardcoded (not random) so running the script reproduces the
# exact checked-in trace, which the btest baseline was captured against.
SRC_ADDR = "2001:db8::527:cdf4"
MULTICAST_GROUP = "ff02::1"

BASE_TIME = 1_700_000_000.0


def create_mld_packet():
    """Create an MLDv1 General Query packet and write it to a pcap file."""
    # Hop limit must be 1 for MLD.
    ipv6 = IPv6(src=SRC_ADDR, dst=MULTICAST_GROUP, hlim=1)

    # Hop-by-Hop options with Router Alert (RFC 2711); value 0 = MLD.
    hopbyhop = IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)])

    # MLDv1 General Query: 10 s max response delay, mladdr :: queries all groups.
    mld_query = ICMPv6MLQuery(mrd=10000, mladdr="::")

    packet = ipv6 / hopbyhop / mld_query
    packet.time = BASE_TIME

    wrpcap(str(Path(__file__).with_suffix("")), packet)


if __name__ == "__main__":
    create_mld_packet()
