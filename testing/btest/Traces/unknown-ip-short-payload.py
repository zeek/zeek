#!/usr/bin/env python3
"""Generate a pcap with unknown IP protocol packets to test short payload handling.

Creates packets using IP protocol 253 (reserved for experimentation/testing per RFC 3692)
with payloads shorter than 8 bytes. This exercises the boundary check in
UnknownIPTransport::DeliverPacket that prevents buffer overrun when calling
PacketContents(data + 8, ...).
"""

from scapy.all import IP, Ether, Raw, wrpcap

packets = []

# Packet with 4-byte payload (shorter than the 8-byte skip in PacketContents)
pkt_short = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    / IP(src="192.168.1.1", dst="192.168.1.2", proto=253)
    / Raw(load=b"\x01\x02\x03\x04")
)
packets.append(pkt_short)

# Packet with 0-byte payload
pkt_empty = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / IP(
    src="192.168.1.1", dst="192.168.1.2", proto=253
)
packets.append(pkt_empty)

# Packet with exactly 8 bytes (boundary case - should produce 0-length contents)
pkt_boundary = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    / IP(src="192.168.1.1", dst="192.168.1.2", proto=253)
    / Raw(load=b"\x01\x02\x03\x04\x05\x06\x07\x08")
)
packets.append(pkt_boundary)

# Packet with 12 bytes (should produce 4-byte contents after skipping 8)
pkt_normal = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    / IP(src="192.168.1.1", dst="192.168.1.2", proto=253)
    / Raw(load=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c")
)
packets.append(pkt_normal)

wrpcap("unknown-ip-short-payload.pcap", packets)
print("Written unknown-ip-short-payload.pcap")
