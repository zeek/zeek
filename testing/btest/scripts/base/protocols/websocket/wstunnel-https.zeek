# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-https.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ts uid history service conn.log
# @TEST-EXEC: btest-diff-cut -m ts uid version server_name ssl_history ssl.log
# @TEST-EXEC: btest-diff-cut -m websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/websocket
