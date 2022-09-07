# @TEST-EXEC: zeek -C -b -r $TRACES/http/http_large_req_8001.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# 
# @TEST-DOC: Tests our DPD signatures with a session where one side exceeds the DPD buffer size.

@load base/protocols/conn
@load base/protocols/http

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	print "http_request", version, method, original_URI;
	}
