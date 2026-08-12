# @TEST-DOC: Check that Reporter::limit_reached_weird functions correctly
# @TEST-EXEC: zeek -r $TRACES/http/get.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/notice/weird

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	Reporter::limit_reached_weird("test_weird_1", c, 10);
	Reporter::limit_reached_weird("test_weird_2", c, 10, 0, "source");
	Reporter::limit_reached_weird("test_weird_3", c, 10, 20);
	}
