# @TEST-DOC: Test Broker WebSocket traffic.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/broker-websocket.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/websocket
