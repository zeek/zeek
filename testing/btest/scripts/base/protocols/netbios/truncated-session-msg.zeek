# @TEST-DOC: Ensures truncated_netbios_message fires. Also used to test avoiding an eager alloc of attacker-controlled length.
#
# @TEST-EXEC: zeek -br $TRACES/netbios/netbios-truncated-session-msg.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_NETBIOSSSN, 139/tcp);
	}
