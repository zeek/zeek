# @TEST-EXEC: zeek -C -b -r $TRACES/wikipedia.trace %INPUT >>output
# @TEST-EXEC: zeek -C -b -r $TRACES/radiotap.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

event new_connection(c: connection)
	{
	if ( c$orig?$l2_addr && c$resp?$l2_addr )
		print c$orig$l2_addr, c$resp$l2_addr;
        else
		print "-", "-";
	}
