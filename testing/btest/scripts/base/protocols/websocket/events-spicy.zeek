# @TEST-DOC: Test WebSocket events of BinPac and Spicy analyzer versions
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
#
# @TEST-EXEC: echo "jupyter-websocket.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES/websocket/jupyter-websocket.pcap %INPUT >>out
# @TEST-EXEC: echo "message-too-big-status.pcap" >>out
# @TEST-EXEC: zeek -b -r $TRACES//websocket/message-too-big-status.pcap %INPUT >>out
#
# @TEST-EXEC: echo "jupyter-websocket.pcap" >>out.spicy
# @TEST-EXEC: zeek -b -r $TRACES/websocket/jupyter-websocket.pcap %INPUT WebSocket::use_spicy_analyzer=T >>out.spicy
# @TEST-EXEC: echo "message-too-big-status.pcap" >>out.spicy
# @TEST-EXEC: zeek -b -r $TRACES//websocket/message-too-big-status.pcap %INPUT WebSocket::use_spicy_analyzer=T >>out.spicy
# @TEST-EXEC: diff -u out.spicy out >&2
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/websocket

redef record connection += {
  ws_data_len: count &default=0;
};

event websocket_established(c: connection, aid: count)
	{
	print "websocket_established", c$uid, aid, c$websocket;
	}

event websocket_message(c: connection, is_orig: bool, opcode: count)
	{
	print "websocket_message", c$uid, is_orig, "opcode", WebSocket::opcodes[opcode], "data_len", c$ws_data_len;
	c$ws_data_len = 0;
	}

event websocket_frame(c: connection, is_orig: bool, fin: bool, rsv: count, opcode: count, payload_len: count)
	{
	print "websocket_frame", c$uid, is_orig, "fin", fin, "rsv", rsv, "opcode", WebSocket::opcodes[opcode], "payload_len", payload_len;
	}

event websocket_frame_data(c: connection, is_orig: bool, data: string)
	{
	# Spicy and binpac differ for data events, just ensure they end up having the same total data length.
	# print "websocket_frame_data", c$uid, is_orig, "len", |data|, "data", data[:120];
	c$ws_data_len += |data|;
	}

event websocket_close(c: connection, is_orig: bool, status: count, reason: string)
	{
	print "websocket_close", c$uid, is_orig, "status", status, "reason", reason;
	}
