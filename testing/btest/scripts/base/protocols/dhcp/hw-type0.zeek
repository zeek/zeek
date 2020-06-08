# @TEST-EXEC: zeek -b -r $TRACES/dhcp/hw-type0.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

const ports = { 67/udp, 68/udp };
redef likely_server_ports += { 67/udp };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCP, ports);
	}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	if ( options?$client_id )
		print "dhcp client_id option", options$client_id;
	}
