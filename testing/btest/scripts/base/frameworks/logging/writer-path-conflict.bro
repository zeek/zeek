# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff reporter.log
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http

event bro_init()
	{
	# Both the default filter for the http stream and this new one will
	# attempt to have the same writer write to path "http", which will
	# be reported as a warning and the write skipped.
	local filter: Log::Filter = [$name="host-only", $include=set("host")];
	Log::add_filter(HTTP::LOG, filter);
	}
