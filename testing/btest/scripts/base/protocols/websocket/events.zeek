# @TEST-DOC: Test WebSocket events.
#
# @TEST-EXEC: echo "jupyter-websocket.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES/websocket/jupyter-websocket.pcap %INPUT >>out
# @TEST-EXEC: echo "wstunnel-http.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-http.pcap %INPUT >>out
# @TEST-EXEC: echo "broker-websocket.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES//websocket/broker-websocket.pcap %INPUT >>out
# @TEST-EXEC: echo "message-too-big-status.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES//websocket/message-too-big-status.pcap %INPUT >>out
# @TEST-EXEC: echo "two-binary-fragments.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES//websocket/two-binary-fragments.pcap %INPUT >>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/websocket

event websocket_established(c: connection, aid: count)
	{
	print "websocket_established", c$uid, aid, c$websocket;
	}

event websocket_message(c: connection, is_orig: bool, opcode: count)
	{
	print "websocket_message", c$uid, is_orig, "opcode", WebSocket::opcodes[opcode];
	}

event websocket_frame(c: connection, is_orig: bool, fin: bool, rsv: count, opcode: count, payload_len: count)
	{
	print "websocket_frame", c$uid, is_orig, "fin", fin, "rsv", rsv, "opcode", WebSocket::opcodes[opcode], "payload_len", payload_len;
	}

event websocket_frame_data(c: connection, is_orig: bool, data: string)
	{
	print "websocket_frame_data", c$uid, is_orig, "len", |data|, "data", data[:120];
	}

event websocket_close(c: connection, is_orig: bool, status: count, reason: string)
	{
	print "websocket_close", c$uid, is_orig, "status", status, "reason", reason;
	}
