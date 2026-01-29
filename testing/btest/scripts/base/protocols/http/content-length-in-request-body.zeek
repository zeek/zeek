# @TEST-DOC: PCAP containing a MIME message as request body with a Content-Length header. Previously this could be used to skip over the next request in a HTTP pipeline.
# @TEST-EXEC: zeek -b -r $TRACES/http/content-length-in-request-body.pcap %INPUT >out
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff out

@load base/frameworks/notice/weird
@load base/protocols/http

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	print "http_request", c$uid, method, original_URI;
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( ! is_orig )
		return;

	print "http_header",  original_name, name, value;
	}
