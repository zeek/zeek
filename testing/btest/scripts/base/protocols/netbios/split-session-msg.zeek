# @TEST-DOC: Verify NetBIOS message body buffering across split TCP deliveries.
#
# @TEST-EXEC: zeek -br $TRACES/netbios/netbios-split-session-msg.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_NETBIOSSSN, 139/tcp);
	}

event netbios_session_message(c: connection, is_orig: bool, msg_type: count,
    data_len: count)
	{
	print "netbios_session_message", is_orig, msg_type, data_len;
	}
