"""
Rewrite the nfs_base.pcap scramble some status and enum values to trigger weirds.
"""
from scapy.all import *

# Packet 25 is an FSINFO reply.
pkts = rdpcap("nfs_base.pcap")
pkt = pkts[24]

# Scramble STATUS NFS3_OK to AAAA
data = bytearray(pkt[Raw].load)
data[28:32] = b'\x41\x41\x41\x41'
pkt[Raw].load = bytes(data)

wrpcap("nfs_fsinfo_bad_status.pcap", pkts)

# Packet 29 is a GETATTR reply. Scramle the ftype from
# directory (2) to BBBB  (\x42\x42\x42\x42) to tickle a weird.
pkts = rdpcap("nfs_base.pcap")
pkt = pkts[28]
data = bytearray(pkt[Raw].load)
data[32:36] = b'\x42\x42\x42\x42'
pkt[Raw].load = bytes(data)
wrpcap("nfs_getattr_bad_ftype.pcap", pkts)


# Packet 44 is a SETATTR call. Scramle the set_it fields for atime and mtime
# to BBBB and CCCC to tickle weirds.
pkts = rdpcap("nfs_base.pcap")
pkt = pkts[43]
data = bytearray(pkt[Raw].load)
data[144:148] = b'\x42\x42\x42\x42'
data[148:152] = b'\x43\x43\x43\x43'
pkt[Raw].load = bytes(data)
wrpcap("nfs_setattr_bad_set_it.pcap", pkts)

# Packet 134 is a WRITE reply. Scramble the committed
# from (2) to CCCC  (\x43\x43\x32\x43) to tickle a weird.
pkts = rdpcap("nfs_write.pcap")
pkt = pkts[133]
data = bytearray(pkt[Raw].load)
data[128:132] = b'\x43\x43\x43\x43'
pkt[Raw].load = bytes(data)
wrpcap("nfs_write_bad_stable_how.pcap", pkts)
