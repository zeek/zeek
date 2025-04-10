# @TEST-DOC: Testing Jupyter WebSocket traffic.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/jupyter-websocket.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
#
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/websocket
