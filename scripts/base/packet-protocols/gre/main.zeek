module PacketAnalyzer::GRE;

export {
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IPTUNNEL &redef;
	const gre_ports = { 4754/udp } &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GRE, gre_ports);
	}
