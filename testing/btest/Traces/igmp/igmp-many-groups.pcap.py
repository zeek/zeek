"""Generate a pcap with IGMP v2 membership reports for many multicast groups.

Outputs igmp-many-groups.pcap containing 150 groups x 3 sources = 450 packets,
each an IGMPv2 Membership Report from a unique source to a distinct multicast
group address (239.0.0.1 through 239.0.0.150).

Generated with assistance from Claude (Anthropic).
"""

from scapy.all import IP, Ether, wrpcap
from scapy.contrib.igmp import IGMP

num_groups = 150
sources_per_group = 3

source_ips = [f"10.0.0.{1 + s}" for s in range(sources_per_group)]
source_macs = [f"00:11:22:00:00:{s:02x}" for s in range(sources_per_group)]

packets = []
for g in range(num_groups):
    group_int = 0xEF000001 + g
    group_ip = f"{(group_int >> 24) & 0xFF}.{(group_int >> 16) & 0xFF}.{(group_int >> 8) & 0xFF}.{group_int & 0xFF}"
    low23 = group_int & 0x007FFFFF
    dst_mac = f"01:00:5e:{(low23 >> 16) & 0xFF:02x}:{(low23 >> 8) & 0xFF:02x}:{low23 & 0xFF:02x}"

    for s in range(sources_per_group):
        pkt = (
            Ether(src=source_macs[s], dst=dst_mac)
            / IP(
                src=source_ips[s],
                dst=group_ip,
                ttl=1,
                id=(g * sources_per_group + s) & 0xFFFF,
            )
            / IGMP(type=0x16, gaddr=group_ip)
        )
        packets.append(pkt)

wrpcap("igmp-many-groups.pcap", packets)
print(
    f"Written pcap with {num_groups} groups x {sources_per_group} sources = {len(packets)} packets"
)
