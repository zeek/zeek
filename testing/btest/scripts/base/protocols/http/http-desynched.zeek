# @TEST-DOC: 5 HTTP requests, the first one is responded to with 3 HTTP responses.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/http-desync-request-response-5.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http

# mime type is irrelevant to this test, so filter it out
event zeek_init()
	{
	Log::remove_default_filter(HTTP::LOG);
	Log::add_filter(HTTP::LOG, [$name="less-mime-types", $exclude=set("mime_type")]);
	}
