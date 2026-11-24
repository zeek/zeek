#!/usr/bin/env python3

"""
Generates a Geneve-encapsulated IGMPv2 trace, the Geneve analog of
tunnels/vxlan-encapsulated-igmp-v2.pcap.

Three IGMPv2 Membership Reports (type 0x16) for 224.0.0.251 are carried
inside an inner Ethernet frame over Geneve (UDP port 6081, protocol type
0x6558 / Transparent Ethernet Bridging), which itself rides on an outer
IPv4/UDP flow.

Written with Claude Opus 4.8 (Anthropic) using Scapy.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, IPOption_Router_Alert, wrpcap
from scapy.contrib.geneve import GENEVE
from scapy.contrib.igmp import IGMP

BASE_TIME = 1_700_000_000.0

# Outer tunnel endpoints, matching the vxlan-encapsulated-igmp-v2.pcap style.
OUTER_ETHER_SRC = "02:42:c5:68:1b:d2"
OUTER_ETHER_DST = "02:42:ac:1e:00:02"
OUTER_IP_SRC = "172.30.0.1"
OUTER_IP_DST = "172.30.0.2"
GENEVE_VNI = 4242
# EtherType 0x6558 == Transparent Ethernet Bridging: the Geneve payload is an
# inner Ethernet frame, like VXLAN.
GENEVE_PROTO_ETHER = 0x6558

MCAST_GROUP = "224.0.0.251"
# Destination MAC for the 224.0.0.251 group (RFC 1112 mapping).
MCAST_MAC = "01:00:5e:00:00:fb"

# (inner source MAC, inner source IP, outer UDP source port, outer IP id)
REPORTS = [
    ("d2:ae:98:40:c2:b5", "192.168.9.80", 48036, 0xBB45),
    ("4a:c2:5f:d3:83:3d", "192.168.9.123", 45303, 0xCDFC),
    ("d2:ae:98:40:c2:b5", "192.168.9.80", 36030, 0x1675),
]


def report(inner_mac, inner_ip, sport, ip_id):
    return (
        Ether(src=OUTER_ETHER_SRC, dst=OUTER_ETHER_DST)
        / IP(src=OUTER_IP_SRC, dst=OUTER_IP_DST, id=ip_id, ttl=64, flags="DF")
        / UDP(sport=sport, dport=6081)
        / GENEVE(proto=GENEVE_PROTO_ETHER, vni=GENEVE_VNI)
        / Ether(src=inner_mac, dst=MCAST_MAC)
        / IP(
            src=inner_ip,
            dst=MCAST_GROUP,
            ttl=1,
            options=[IPOption_Router_Alert()],
        )
        # IGMPv2 Membership Report; Max Resp Time is 0 in reports.
        / IGMP(type=0x16, mrcode=0, gaddr=MCAST_GROUP)
    )


packets = [report(*args) for args in REPORTS]

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
