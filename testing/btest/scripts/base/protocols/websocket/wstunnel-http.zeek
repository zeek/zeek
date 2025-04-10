# @TEST-DOC: Test HTTP connection tunneled within WebSocket using wstunnel. Seems something in the HTTP scripts gets confused :-/
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-http.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid host uri status_code user_agent < http.log > http.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/websocket
