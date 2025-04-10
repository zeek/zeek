# @TEST-DOC: Test no analysis of tunneled WebSocket when the analyzer is globally disabled.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut

# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: test ! -f websocket.log
# @TEST-EXEC: test ! -f ssh.log
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/websocket

redef Analyzer::disabled_analyzers += {
	Analyzer::ANALYZER_WEBSOCKET,
};
