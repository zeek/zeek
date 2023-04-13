module PacketAnalyzer::GRE;

export {
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IPTUNNEL &redef;
}

event zeek_init() &priority=20
	{
	# ARUBA
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8200, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8210, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8220, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8230, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8240, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8250, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8260, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8270, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8280, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8290, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82A0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82B0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82C0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82D0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82E0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x82F0, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8300, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8310, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8320, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8330, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8340, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8350, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8360, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8370, PacketAnalyzer::ANALYZER_IEEE802_11);
	# TODO: how to handle 0x9000 here, which should just be dropped?
	}