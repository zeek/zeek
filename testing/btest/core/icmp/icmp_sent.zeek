# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp_sent.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event icmp_sent(c: connection, icmp: icmp_conn)
	{
	print "icmp_sent", c$id, icmp;
	}

event icmp_sent_payload(c: connection, icmp: icmp_conn, payload: string)
	{
	print "icmp_sent_payload", c$id, icmp, |payload|;
	}
