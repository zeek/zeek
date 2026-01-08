# @TEST-DOC: Test HTTP connection tunneled within WebSocket using wstunnel. Seems something in the HTTP scripts gets confused :-/
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-http.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ts uid history service conn.log
# @TEST-EXEC: btest-diff-cut -m ts uid host uri status_code user_agent http.log
# @TEST-EXEC: btest-diff-cut -m websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/websocket
