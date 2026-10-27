module PacketAnalyzer::L2TP;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_PPP &redef;

	## The set of UDP ports used for L2TP tunnels.
	const l2tp_ports = { 1701/udp } &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_L2TP, l2tp_ports);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_L2TP, 0x05, PacketAnalyzer::ANALYZER_ETHERNET);
	}
