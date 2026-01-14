# @TEST-DOC: Testing Jupyter WebSocket traffic.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/jupyter-websocket.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ts uid history service conn.log
# @TEST-EXEC: btest-diff-cut -m websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/websocket
