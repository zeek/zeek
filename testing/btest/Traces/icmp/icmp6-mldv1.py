#!/usr/bin/env python3
"""
Script to create ICMPv6 Multicast Listener Discovery (MLD) messages using Scapy.
"""

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

# Configuration
SRC_ADDR = "fe80::1c8c:7488:34cf:cbdb"
MULTICAST_ADDR = "ff02::1:ff9a:3b7c"

# Create MLD Multicast Listener Report packet (without hop-by-hop)
mld_report = (
    Ether()
    / IPv6(src=SRC_ADDR, dst=MULTICAST_ADDR, hlim=1)
    / ICMPv6MLReport(mladdr=MULTICAST_ADDR)
)

# Create MLD Multicast Listener Done packet (without hop-by-hop)
mld_done = (
    Ether()
    / IPv6(src=SRC_ADDR, dst=MULTICAST_ADDR, hlim=1)
    / ICMPv6MLDone(mladdr=MULTICAST_ADDR)
)

# Create MLD Multicast Listener Report packet with hop-by-hop options
# Router Alert option tells routers to examine the packet
mld_report_hbh = (
    Ether()
    / IPv6(src=SRC_ADDR, dst=MULTICAST_ADDR, hlim=1)
    / IPv6ExtHdrHopByHop(options=[RouterAlert(), PadN(optdata=b"\x00\x00")])
    / ICMPv6MLReport(mladdr=MULTICAST_ADDR)
)

# Create MLD Multicast Listener Done packet with hop-by-hop options
mld_done_hbh = (
    Ether()
    / IPv6(src=SRC_ADDR, dst=MULTICAST_ADDR, hlim=1)
    / IPv6ExtHdrHopByHop(options=[RouterAlert(), PadN(optdata=b"\x00\x00")])
    / ICMPv6MLDone(mladdr=MULTICAST_ADDR)
)

print("MLD Report packet (without hop-by-hop):")
mld_report.show()

print("\nMLD Done packet (without hop-by-hop):")
mld_done.show()

print("\nMLD Report packet (with hop-by-hop):")
mld_report_hbh.show()

print("\nMLD Done packet (with hop-by-hop):")
mld_done_hbh.show()

# Write all packets to pcap file
wrpcap("icmp6-mldv1.pcap", [mld_report, mld_done, mld_report_hbh, mld_done_hbh])
print("\nAll packets written to icmp6-mldv1.pcap")
