# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-https.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid version server_name ssl_history < ssl.log > ssl.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/websocket
