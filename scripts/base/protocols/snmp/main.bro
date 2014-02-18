##! Enables analysis of SNMP datagrams.

module SNMP;

export {
}

const ports = { 161/udp, 162/udp };

redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SNMP, ports);
	}
