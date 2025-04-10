# This tests that the HTTP analyzer upgrades to the WebSocket analyzer.
#
# Further, we implement a WebSocket::configure_analyzer() hook to prevent
# DPD on the inner connection.
#
# @TEST-EXEC: zeek -r $TRACES/http/websocket.pcap %INPUT
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: btest-diff .stdout

event http_connection_upgrade(c: connection, protocol: string)
	{
	print fmt("Connection upgraded to %s", protocol);
	}

hook WebSocket::configure_analyzer(c: connection, aid: count, config: WebSocket::AnalyzerConfig)
	{
	if ( ! config?$subprotocol )
		return;

	print "WebSocket::configure_analyzer", c$uid, aid, config$subprotocol;
	if ( config$subprotocol == "x-kaazing-handshake" )
		# The originator's WebSocket frames match HTTP, so DPD would
		# enable HTTP for the frame's payload, but the responder's frames
		# contain some ack/status junk just before HTTP response that
		# trigger a violation. Disable DPD for to prevent a analyzer_failed.log
		# entry.
		config$use_dpd = F;
	}
