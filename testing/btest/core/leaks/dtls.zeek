# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/tls/dtls1_0.pcap %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load base/protocols/ssl

event ssl_established(c: connection) &priority=3
	{
	print "established";
	}
