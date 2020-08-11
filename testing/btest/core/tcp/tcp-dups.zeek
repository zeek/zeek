# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/ssh-dups.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event tcp_multiple_retransmissions(c: connection, is_orig: bool, threshold: count)
	{
	print "RETRANSMITS:", c$id, is_orig, threshold, c$history;
	}

event connection_state_remove(c: connection)
	{
	print "REMOVE:", c$id, c$history;
	}
