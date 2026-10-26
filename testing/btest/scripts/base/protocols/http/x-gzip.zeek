# @TEST-EXEC: zeek -b -r $TRACES/http/x-gzip.pcap base/protocols/http %INPUT >out
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff out

event zip_analyzer_stats(c: connection, aid: count, total_in: count, total_out: count, exceeded: bool)
	{
	print fmt("zip stats: in=%d out=%d exceeded=%s", total_in, total_out, exceeded);
	}
