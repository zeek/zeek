# @TEST-EXEC: zeek -b -r $TRACES/http/pipelined-requests.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

global msg_count: table[conn_id] of count &default=0;

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=10
	{
	if ( atype != Analyzer::ANALYZER_HTTP )
		return;

	print "proto confirm", atype;
	print disable_analyzer(info$c$id, info$aid, T, T);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	++msg_count[c$id];
	print "http_request", method, original_URI;
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	++msg_count[c$id];
	print "http_reply", code;
	}

event zeek_done()
	{
	print "total http messages", msg_count;
	}
