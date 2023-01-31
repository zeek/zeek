# @TEST-DOC: Disable the analyzer if 5 or more messages have been seen on a connection.
# @TEST-EXEC: zeek -b -r $TRACES/http/pipelined-requests.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

global msg_count: table[conn_id] of count &default=0;

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=10
	{
	if ( atype != Analyzer::ANALYZER_HTTP )
		return;

	print "proto confirm", atype;
	}

# Prevent disabling all analyzers.
hook Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count)
	{
	if ( msg_count[c$id] < 4 )
		{
		print "preventing disable_analyzer", c$id, atype, aid, msg_count[c$id];
		break;
		}

	print "allowing disable_analyzer", c$id, atype, aid, msg_count[c$id];
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	++msg_count[c$id];
	print "http_request", method, original_URI;
	print disable_analyzer(c$id, current_analyzer(), T, T);
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
