# @TEST-DOC: Test SSH connection tunneled within WebSocket using wstunnel, comparing BinPac and Spicy.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m ts uid client server auth_success auth_attempts kex_alg host_key_alg < ssh.log > ssh.log.cut
# @TEST-EXEC: rm -v *log
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wstunnel-ssh.pcap WebSocket::use_spicy_analyzer=T %INPUT
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut.spicy
# @TEST-EXEC: zeek-cut -m ts uid client server auth_success auth_attempts kex_alg host_key_alg < ssh.log > ssh.log.cut.spicy
#
# @TEST-EXEC: diff -u conn.log.cut.spicy  conn.log.cut >&2
# @TEST-EXEC: diff -u ssh.log.cut.spicy  ssh.log.cut >&2
# @TEST-EXEC: btest-diff conn.log.cut.spicy
# @TEST-EXEC: btest-diff ssh.log.cut.spicy
# @TEST-EXEC: test ! -f analyzer_failed.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/websocket

# Make conn.log compatible, the spicy version uses SPICY_ANALYZER, so need
# to normalize the c$service entry (and do it in either case to keep determinism).
event connection_state_remove(c: connection) &priority=10
	{
	if ( "SPICY_WEBSOCKET" in c$service || "WEBSOCKET" in c$service )
		{
		delete c$service["SPICY_WEBSOCKET"];
		delete c$service["WEBSOCKET"];
		add c$service["WEBSOCKET"];
		}
	}
