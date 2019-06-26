# @TEST-EXEC: zeek -r $TRACES/http/pipelined-requests.trace %INPUT > output
# @TEST-EXEC: btest-diff http.log

# mime type is irrelevant to this test, so filter it out
event zeek_init()
	{
	Log::remove_default_filter(HTTP::LOG);
	Log::add_filter(HTTP::LOG, [$name="less-mime-types", $exclude=set("mime_type")]);
	}
