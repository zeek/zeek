"""
Rewrite the mount-unmount.pcap to scramble the MOUNT status and the auth flavors.
"""

from scapy.all import Raw, rdpcap, wrpcap

pkts = rdpcap("mount-unmount.pcap")

# Packet 6 (index 5) is the MNT reply. Override the status to AAAA.
pkt = pkts[5]
data_orig = bytes(pkt[Raw].load)

# Scramble mount status.
data = bytearray(data_orig)
data[24:28] = b"\x42\x42\x42\x42"
pkt[Raw].load = bytes(data)
wrpcap("mount-unmount-bad-status.pcap", pkts)

# Scramble auth flavor.
data = bytearray(data_orig)
data[64:68] = b"\x42\x42\x42\x42"
pkt[Raw].load = bytes(data)
wrpcap("mount-unmount-bad-auth-flavor.pcap", pkts)
