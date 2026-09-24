module PacketAnalyzer::GRE;

export {
	const gre_ports = { 4754/udp } &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GRE, gre_ports);

	# IP
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x86DD, PacketAnalyzer::ANALYZER_IP);

	# MPLS
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8847, PacketAnalyzer::ANALYZER_MPLS);

	# Transparent Ethernet bridging
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);

	# ERSPAN Type II (0x88be with sequence bit - GRE routes here)
	# ERSPAN Type III (0x22eb)
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x88be, PacketAnalyzer::ANALYZER_ERSPAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x22eb, PacketAnalyzer::ANALYZER_ERSPAN);

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
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x9000, PacketAnalyzer::ANALYZER_IEEE802_11);
	}
