# @TEST-DOC: Verify VLANs parse PCP and DEI bits
#
# See the end of the file for instructions to create the pcap.
#
# @TEST-EXEC: zeek -r $TRACES/vlan-pcp-dei.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

event raw_packet(p: raw_pkt_hdr)
	{
	if ( p$l2?$vlan )
		print fmt("Found packet with VLAN ID: %d, PCP: %d, and DEI: %s", p$l2$vlan,
		    p$l2$vlan_pcp, p$l2$vlan_dei);
	else
		print "No vlan found!";

	if ( p$l2?$inner_vlan )
		{
		assert p$l2?$vlan;
		print fmt("Found packet with inner VLAN ID: %d, inner PCP: %d, and inner DEI: %s",
		    p$l2$inner_vlan, p$l2$inner_vlan_pcp, p$l2$inner_vlan_dei);
		}
	}

# The pcap is completely artificial, first with some in.pcap made via:
#
# #!/usr/bin/env python3
# from scapy.all import *
# wrpcap(
#     "in.pcap",
#     [
#         Ether()
#         / IP(src="192.168.1.100", dst="192.168.1.200")
#         / TCP(sport=12345, dport=80, flags="S", seq=1000),
#         Ether()
#         / IP(src="192.168.1.200", dst="192.168.1.100")
#         / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001),
#         Ether()
#         / IP(src="192.168.1.100", dst="192.168.1.200")
#         / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001),
#     ],
# )
#
# Then with a couple of rewrites:
#
# $ tcprewrite --enet-vlan=add --enet-vlan-tag 20 --enet-vlan-cfi=1 --enet-vlan-pri=5 -i in.pcap -o tagged_1.pcap
# $ tcprewrite --enet-vlan=add --enet-vlan-tag 10 --enet-vlan-cfi=0 --enet-vlan-pri=7 -i tagged_1.pcap -o tagged_2.pcap
# $ mergecap -w vlan-test.pcap in.pcap tagged_1.pcap tagged_2.pcap
