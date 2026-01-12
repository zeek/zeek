# @TEST-DOC: PCAP extracted from the m57-long test - single HTTP connection with byterange downloads for different files.
#
# XXX: Note that the connection has gaps and Zeek stops analyzing part way through the second response!
#
# @TEST-EXEC: zeek -b -r $TRACES/http/m57-long-49583-80.pcap %INPUT >out
#
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p service history orig_bytes resp_bytes missed_bytes < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: zeek-cut -m < files.log > files.log.cut
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff files.log.cut

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/http

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	print "http_request", c$uid, method, original_URI;
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( name == "CONTENT-RANGE" )
		print "http_header",  c$uid, is_orig, original_name, value;
	}
