# @TEST-EXEC: bro -r $TRACES/http-pipelined-requests.trace %INPUT > output
# @TEST-EXEC: btest-diff http.log

# mime type is irrelevant to this test, so filter it out
event bro_init()
	{
	Log::remove_default_filter(HTTP::HTTP);
	Log::add_filter(HTTP::HTTP, [$name="less-mime-types", $exclude=set("mime_type")]);
	}
