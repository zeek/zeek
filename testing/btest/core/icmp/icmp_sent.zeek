# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp_sent.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event icmp_sent(c: connection, info: icmp_info)
	{
	print "icmp_sent", c$id, info;
	}

event icmp_sent_payload(c: connection, info: icmp_info, payload: string)
	{
	print "icmp_sent_payload", c$id, info, |payload|;
	}
