# @TEST-DOC: Test cases where HTTP transfer-encoding has multiple comma-separated values
#
# @TEST-EXEC: zeek -b -r $TRACES/http/transfer-encoding-gzip-chunked.pcap %INPUT > out
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff-cut -m http.log
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird

event http_header(c: connection, is_orig: bool, original_name: string, name: string, val: string)
	{
	print "http_header", is_orig, name, val;
	}
