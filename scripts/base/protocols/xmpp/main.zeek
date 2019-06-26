
module XMPP;

const ports = { 5222/tcp, 5269/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_XMPP, ports);
	}

