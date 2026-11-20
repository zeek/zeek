# @TEST-DOC: Without the bt_tracker_request() or bt_tracker_response(), previously the Bittorrent analyzer would leak memory.

# @TEST-EXEC: zeek -b -C -r $TRACES/bittorrent/bittorrent-tracker-eventless-table-memory-exhaustion.pcap %INPUT >output
#
# @TEST-EXEC: btest-diff-cut uid service history conn.log
# @TEST-EXEC: btest-diff output

@load base/protocols/conn

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_BITTORRENTTRACKER, 6969/tcp);
	}

event connection_state_remove(c: connection)
	{
	print c$uid, cat(c$service);
	}
