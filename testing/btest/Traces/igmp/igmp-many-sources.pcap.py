"""Generate a pcap with IGMP v2 membership reports from many sources to one group.

Outputs igmp-many-sources.pcap containing 150 packets, each an IGMPv2
Membership Report from a different source IP (10.0.0.1 through 10.0.0.150)
to the same multicast group 239.1.1.1.

Generated with assistance from Claude (Anthropic), adapted with Claude
Sonnet 5.5 (Anthropic) to write beside the script and use fixed timestamps so
the trace is reproducible.
"""

from pathlib import Path

from scapy.all import IP, Ether, wrpcap
from scapy.contrib.igmp import IGMP

BASE_TIME = 1_700_000_000.0

multicast_group = "239.1.1.1"
dst_mac = "01:00:5e:01:01:01"
num_hosts = 150

packets = []
for i in range(num_hosts):
    src_ip = (
        f"10.0.0.{1 + i}"
        if (1 + i) <= 255
        else f"10.0.{((1 + i) >> 8) & 0xFF}.{(1 + i) & 0xFF}"
    )
    src_mac = f"00:11:22:{(i >> 16) & 0xFF:02x}:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}"

    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=multicast_group, ttl=1, id=i & 0xFFFF)
        / IGMP(type=0x16, gaddr=multicast_group)
    )
    packets.append(pkt)

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
