# @TEST-EXEC: zeek -b -r $TRACES/raw_packets.pcap %INPUT >output
# @TEST-EXEC: zeek -b -r $TRACES/icmp_dot1q.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

event raw_packet(p: raw_pkt_hdr)
	{
	print p;
	}

