# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel, attaches HTTP analyzer instead of SSH.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f ssh.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/websocket

hook WebSocket::configure_analyzer(c: connection, aid: count, config: WebSocket::AnalyzerConfig)
	{
	print "WebSocket::configure_analyzer", c$uid, aid;
	config$analyzer = Analyzer::ANALYZER_HTTP;  # this is obviously wrong :-)
	}
