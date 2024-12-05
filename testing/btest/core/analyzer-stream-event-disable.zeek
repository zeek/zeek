# @TEST-DOC: Show-case disable_analyzer() for ANALYZER_STREAM_EVENT after receiving a few events.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_STREAM_EVENT, 80/tcp);
	}


event new_connection(c: connection)
	{
	print c$uid, "new_connection";
	}

global deliveries = 0;

event stream_deliver(c: connection, is_orig: bool, data: string)
	{
	++deliveries;
	print c$uid, is_orig, |data|, data[:32];

	if ( deliveries == 2 )
		disable_analyzer(c$id, current_analyzer());
	}

event connection_state_remove(c: connection)
	{
	print c$uid, "connection_state_remove";
	}
