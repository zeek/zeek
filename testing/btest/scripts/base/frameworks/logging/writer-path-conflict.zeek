# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff reporter.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff http-2.log
# @TEST-EXEC: btest-diff http-3.log
# @TEST-EXEC: btest-diff http-2-2.log

@load base/protocols/http

event zeek_init()
	{
	# Both the default filter for the http stream and this new one will
	# attempt to have the same writer write to path "http", which will
	# be reported as a warning and the path auto-corrected to "http-2"
	local filter: Log::Filter = [$name="host-only", $include=set("host")];
	# Same deal here, but should be auto-corrected to "http-3".
	local filter2: Log::Filter = [$name="uri-only", $include=set("uri")];
	# Conflict between auto-correct paths needs to be corrected, too, this
	# time it will be "http-2-2".
	local filter3: Log::Filter = [$path="http-2", $name="status-only", $include=set("status_code")];
	Log::add_filter(HTTP::LOG, filter);
	Log::add_filter(HTTP::LOG, filter2);
	Log::add_filter(HTTP::LOG, filter3);
	}
