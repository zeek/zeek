# @TEST-DOC: Test a HTTP request tunneled within WebSocket where the HTTP reply is fragmented. This wasn't handled properly in the first iteration.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/fragmented-http-reply.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/websocket

# Only print http_headers after the websocket_established() event
# to reduce the noise. There' a HTTP request within the WebSocket
# tunnel.
global ws = F;

event websocket_established(c: connection, aid: count)
	{
	ws = T;
	print "websocket_established";
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, val: string)
	{
	if ( ws )
		print "http_header", is_orig, name, val;
	}
