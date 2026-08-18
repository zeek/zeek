# @TEST-DOC: Test connection_exists() within new_connection() for ICMP traces. Regression test for #4645.
#
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-ip.pcap %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-no-context.pcap %INPUT
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-udp.pcap %INPUT

# @TEST-EXEC: btest-diff-remove-abspath .stderr

event new_connection(c: connection)
	{
	assert connection_exists(c$id), fmt("%s does not exist (pcap %s)", c$id, split_string(packet_source()$path, /\//)[-1]);
	}
