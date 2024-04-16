# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel, configure SSH analyzer via hook explicitly.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid client server auth_success auth_attempts kex_alg host_key_alg < ssh.log > ssh.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssh.log.cut
# @TEST-EXEC: btest-diff websocket.log
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
