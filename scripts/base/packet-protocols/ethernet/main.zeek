module PacketAnalyzer::ETHERNET;

export
	{
	# We use some magic numbers here to denote these. The values here are outside the range of the
	# standard ethertypes, which should always be above 1536.
	const SNAP_FORWARDING_KEY : count = 0x0001;
	const NOVELL_FORWARDING_KEY : count = 0x0002;
	const LLC_FORWARDING_KEY : count = 0x0003;
	}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8847, PacketAnalyzer::ANALYZER_MPLS);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88E7, PacketAnalyzer::ANALYZER_PBB);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8035, PacketAnalyzer::ANALYZER_ARP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88A8, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x9100, PacketAnalyzer::ANALYZER_VLAN);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8864, PacketAnalyzer::ANALYZER_PPPOE);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8926, PacketAnalyzer::ANALYZER_VNTAG);

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, SNAP_FORWARDING_KEY,
	                                         PacketAnalyzer::ANALYZER_SNAP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, NOVELL_FORWARDING_KEY,
	                                         PacketAnalyzer::ANALYZER_NOVELL_802_3);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, LLC_FORWARDING_KEY,
	                                         PacketAnalyzer::ANALYZER_LLC);
	}
