# @TEST-DOC: Verify fragmented WebSocket state survives split final-frame payload delivery.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/websocket/fragmented-message-state.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/frameworks/notice/weird
@load base/protocols/websocket

redef WebSocket::use_spicy_analyzer = F;

global frame_count = 0;
global message_count = 0;
global data_bytes = 0;

event websocket_frame(c: connection, is_orig: bool, fin: bool, rsv: count,
                      opcode: count, payload_len: count)
	{
	++frame_count;
	}

event websocket_message(c: connection, is_orig: bool, opcode: count)
	{
	++message_count;
	}

event websocket_frame_data(c: connection, is_orig: bool, data: string)
	{
	data_bytes += |data|;
	}

event zeek_done()
	{
	print "frames", frame_count;
	print "messages", message_count;
	print "data bytes", data_bytes;
	}
