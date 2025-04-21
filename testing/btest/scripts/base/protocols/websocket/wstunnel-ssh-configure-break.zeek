# @TEST-DOC: Test that breaking from configure_analyzer() removes the attached analyzer.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT >out 2>&1
#
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut

# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: test ! -f ssh.log
# @TEST-EXEC: test ! -f analyzer_failed.log

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/websocket

hook WebSocket::configure_analyzer(c: connection, aid: count, config: WebSocket::AnalyzerConfig)
	{
	print "WebSocket::configure_analyzer", c$uid, aid;
	break;
	}

# These should never be raised
event websocket_message(c: connection, is_orig: bool, opcode: count)
	{
	print "ERROR: websocket_message", c$uid, is_orig, "opcode", WebSocket::opcodes[opcode];
	}

hook Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count)
	{
	print "disabling_analyzer", c$uid, atype, aid;
	}
