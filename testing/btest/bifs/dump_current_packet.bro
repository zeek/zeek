# @TEST-EXEC: bro -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff 1.pcap
# @TEST-EXEC: btest-diff 2.pcap

global i: count = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	++i;
	dump_current_packet(cat(i, ".pcap"));
	if ( i >= 3 )
		terminate();
	}
