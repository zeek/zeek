# @TEST-EXEC: zeek -b -r $TRACES/raw_packets.trace %INPUT >output
# @TEST-EXEC: zeek -b -r $TRACES/icmp_dot1q.trace %INPUT >>output
# @TEST-EXEC: btest-diff output

event raw_packet(p: raw_pkt_hdr)
	{
	print p;
	}

