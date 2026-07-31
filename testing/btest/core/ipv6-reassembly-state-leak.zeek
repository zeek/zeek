# @TEST-DOC: Test that unprocessed IPv6 fragments don't cause unbounded growth
# @TEST-EXEC: zeek -b -r $TRACES/ipv6-reassembly-state-leak.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird

event zeek_done()
	{
	local stats = get_conn_stats();

	# Fragments with bad header sizes should automatically be removed
	# from the manager. This should never grow more than 1.
	print fmt("max fragments seen: %d", stats$max_fragments);
	}
