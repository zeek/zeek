# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_STREAM_EVENT, 80/tcp);
	}

event stream_deliver(c: connection, is_orig: bool, data: string)
	{
	print c$uid, is_orig, |data|, data[:32];
	}
