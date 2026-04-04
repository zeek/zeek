# @TEST-DOC: PCAP extracted from the CTU-SME-11 Windows7AD baseline
# @TEST-EXEC: zeek -b -r $TRACES/http/ctu-62604-80.pcap %INPUT >out
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff out

@load base/frameworks/notice/weird
@load base/protocols/http

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( ! is_orig )
		return;

	print "http_header",  original_name, name, value, "c$http$orig_mime_depth", c$http$orig_mime_depth;
	}
