# @TEST-DOC: Hook Analyzer::disabling_analyzer in a module
# @TEST-EXEC: zeek -b -r $TRACES/http/pipelined-requests.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/http

module MyHTTP;


# Prevent disabling all analyzers.
hook Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count)
	{
	print("prevent disabling");
	break;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	print "http_request", method, original_URI;
	print disable_analyzer(c$id, current_analyzer(), T, T);
	}
