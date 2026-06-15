# @TEST-DOC: Ensures frames cannot close with over than 125 bytes (the RFC limit)
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=F %INPUT WebSocket::max_control_frame_size=0
# @TEST-EXEC: ! test -f weird.log
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=F %INPUT
# @TEST-EXEC: mv weird.log weird-pac.log
# @TEST-EXEC: btest-diff weird-pac.log
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=T %INPUT WebSocket::max_control_frame_size=0
# @TEST-EXEC: ! test -f weird.log
#
# @TEST-EXEC: zeek -br $TRACES/websocket/oversized-close-frame.pcapng WebSocket::use_spicy_analyzer=T %INPUT
# @TEST-EXEC: mv weird.log weird-spicy.log
# @TEST-EXEC: btest-diff weird-spicy.log

@load base/protocols/websocket
@load base/frameworks/notice/weird
