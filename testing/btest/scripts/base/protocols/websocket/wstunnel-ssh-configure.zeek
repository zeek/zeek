# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel, configure SSH analyzer via hook explicitly.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ts uid history service conn.log
# @TEST-EXEC: btest-diff-cut -m ts uid client server auth_success auth_attempts kex_alg host_key_alg ssh.log
# @TEST-EXEC: btest-diff-cut -m websocket.log
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/websocket

hook WebSocket::configure_analyzer(c: connection, aid: count, config: WebSocket::AnalyzerConfig)
	{
	print "WebSocket::configure_analyzer", c$uid, aid;
	config$analyzer = Analyzer::ANALYZER_SSH;
	}
