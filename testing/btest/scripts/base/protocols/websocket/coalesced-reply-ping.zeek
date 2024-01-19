# @TEST-DOC: The reply-ping-coalesced pcap contains a WebSocket ping message right after the HTTP reply, in the same packet.

# @TEST-EXEC: zeek -b -r $TRACES/websocket/reply-ping-separate.pcap %INPUT >>out-separate
# @TEST-EXEC: test ! -f weird.log
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/reply-ping-coalesced.pcap %INPUT >>out-coalesced
# @TEST-EXEC: btest-diff out-separate
# @TEST-EXEC: btest-diff out-coalesced
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: diff out-separate out-coalesced
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/websocket

event websocket_established(c: connection, aid: count)
	{
	print "websocket_established", c$uid, aid;
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
