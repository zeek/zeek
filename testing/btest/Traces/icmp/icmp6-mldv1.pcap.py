#!/usr/bin/env python3
"""
Script to create ICMPv6 Multicast Listener Discovery (MLDv1) messages using Scapy.

Writes four packets beside this script: a Multicast Listener Report and a Done,
each both without and with a Hop-by-Hop Router Alert option (RFC 2711).

Generated with Claude Sonnet 4.6 (Anthropic), adapted with Claude Sonnet 5.5
(Anthropic) to write beside the script and use fixed timestamps so the trace is
reproducible.
"""

from pathlib import Path

from scapy.all import (
    Ether,
    ICMPv6MLDone,
    ICMPv6MLReport,
    IPv6,
    IPv6ExtHdrHopByHop,
    PadN,
    RouterAlert,
    wrpcap,
)

SRC_ADDR = "fe80::1c8c:7488:34cf:cbdb"
MULTICAST_ADDR = "ff02::1:ff9a:3b7c"

# Pin the Ethernet addresses to fixed literals. A bare Ether() resolves its
# source MAC by routing to the L3 destination, which leaks the host NIC MAC into
# the trace and warns/fails where there is no IPv6 route (e.g. in Docker),
# producing environment-dependent bytes. SRC_MAC is an arbitrary locally
# administered address; DST_MAC is the IPv6 multicast MAC for MULTICAST_ADDR
# (33:33 + its low 32 bits, ff9a:3b7c), which is what Scapy derived here anyway.
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "33:33:ff:9a:3b:7c"

BASE_TIME = 1_700_000_000.0

# Router Alert option tells routers to examine the packet.
hbh = IPv6ExtHdrHopByHop(options=[RouterAlert(), PadN(optdata=b"\x00\x00")])


def eth():
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ipv6():
    return IPv6(src=SRC_ADDR, dst=MULTICAST_ADDR, hlim=1)


packets = [
    # Report and Done without hop-by-hop options.
    eth() / ipv6() / ICMPv6MLReport(mladdr=MULTICAST_ADDR),
    eth() / ipv6() / ICMPv6MLDone(mladdr=MULTICAST_ADDR),
    # Report and Done with hop-by-hop options.
    eth() / ipv6() / hbh / ICMPv6MLReport(mladdr=MULTICAST_ADDR),
    eth() / ipv6() / hbh / ICMPv6MLDone(mladdr=MULTICAST_ADDR),
]

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
