# @TEST-DOC: The TCPSTATS analyzer is disabled by default. This smoke checks it is working when enabled.
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/ssh-dups.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Analyzer::enable_analyzer(Analyzer::ANALYZER_TCPSTATS);
	}

event conn_stats(c: connection, os: endpoint_stats, rs: endpoint_stats)
	{
	print c$uid, os, rs;
	}
