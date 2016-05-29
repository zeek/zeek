# @TEST-EXEC: bro -C -b -r $TRACES/wikipedia.trace %INPUT >>output
# @TEST-EXEC: bro -C -b -r $TRACES/radiotap.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

event new_connection(c: connection)
	{
	if ( c?$eth_src && c?$eth_dst )
		print c$eth_src, c$eth_dst;
        else
		print "-", "-";
	}
