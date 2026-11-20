# @TEST-DOC: Use a FIN flood for testing connection's history capping

# @TEST-EXEC: zeek -b -r $TRACES/tcp/fin-flood.pcap %INPUT >out

# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/frameworks/notice/weird

# Unsetting this would make the history length 103 (100 FINs + three-way-handshake)
redef max_connection_history_size = 100;

event connection_state_remove(c: connection)
	{
	print c$history, |c$history|;
	}
