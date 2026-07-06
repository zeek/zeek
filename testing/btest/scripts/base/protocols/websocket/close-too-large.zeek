# @TEST-DOC: Ensures frames cannot close with over than 125 bytes (the RFC limit)
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=F %INPUT WebSocket::max_control_frame_size=0 >out-pac-uncapped
# @TEST-EXEC: ! test -f weird.log
# @TEST-EXEC: btest-diff out-pac-uncapped
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=F %INPUT >out-pac-capped
# @TEST-EXEC: mv weird.log weird-pac.log
# @TEST-EXEC: btest-diff weird-pac.log
# @TEST-EXEC: btest-diff out-pac-capped
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=T %INPUT WebSocket::max_control_frame_size=0 >out-spicy-uncapped
# @TEST-EXEC: ! test -f weird.log
# @TEST-EXEC: btest-diff out-spicy-uncapped
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=T %INPUT >out-spicy-capped
# @TEST-EXEC: mv weird.log weird-spicy.log
# @TEST-EXEC: btest-diff weird-spicy.log
# @TEST-EXEC: btest-diff out-spicy-capped

@load base/protocols/websocket
@load base/frameworks/notice/weird

event websocket_close(c: connection, is_orig: bool, status: count, reason: string) {
	print fmt("Close length: %d", |reason|);
}
