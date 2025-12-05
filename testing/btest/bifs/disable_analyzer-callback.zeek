# @TEST-DOC: A version of bifs/disable_analyzer that uses a confirmation handler instead of analyzer_confirmation_info
# @TEST-EXEC: zeek -b -r $TRACES/http/pipelined-requests.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

global msg_count: table[conn_id] of count &default=0;

module Analyzer;

event my_confirmation_handler(tag: Tag, info: AnalyzerConfirmationInfo)
	{
	if ( tag != ANALYZER_HTTP )
		print "bad invocation of handler", tag;

	print "proto confirm", tag;
	}

event zeek_init()
	{
	register_confirmation_handler(ANALYZER_HTTP, my_confirmation_handler);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	++msg_count[c$id];
	print "http_request", method, original_URI;
	print ::disable_analyzer(c$id, current_analyzer(), T, T);
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
