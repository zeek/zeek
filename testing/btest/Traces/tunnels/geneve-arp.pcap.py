#!/usr/bin/env python3

"""
Generates a packet capture with a well-formed ARP request in Geneve tunnel.
"""

import sys

from scapy.all import ARP, IP, UDP, Ether, wrpcap
from scapy.contrib.geneve import GENEVE

pkt = (
    Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb")
    / IP(src="10.0.0.1", dst="10.0.0.2", id=1, ttl=64)
    / UDP(sport=12345, dport=6081)
    / GENEVE(proto=0x0806, vni=1)
    / ARP(
        hwsrc="aa:bb:cc:dd:ee:ff",
        psrc="10.0.0.1",
        hwdst="00:00:00:00:00:00",
        pdst="10.0.0.2",
    )
)

outfile = sys.argv[1] if len(sys.argv) > 1 else "geneve-arp.pcap"
wrpcap(outfile, pkt)
print("wrote pcap, frame len =", len(bytes(pkt)))
