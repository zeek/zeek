module OpenVPN;

const ports = { 1194/udp, 1195/udp, 1196/udp, 1197/udp };

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_OPENVPN, ports);
	}
