module PacketAnalyzer::ROOT;

export {
	## Default analyzer (if we don't know the link type, we assume raw IP)
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const DLT_EN10MB : count = 1;
const DLT_FDDI : count = 10;
const DLT_IEEE802_11 : count = 105;
const DLT_IEEE802_11_RADIO : count = 127;
const DLT_LINUX_SLL : count = 113;
const DLT_LINUX_SLL2 : count = 276;
const DLT_NFLOG : count = 239;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_EN10MB, PacketAnalyzer::ANALYZER_ETHERNET);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_FDDI, PacketAnalyzer::ANALYZER_FDDI);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_IEEE802_11, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_IEEE802_11_RADIO, PacketAnalyzer::ANALYZER_IEEE802_11_RADIO);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_LINUX_SLL, PacketAnalyzer::ANALYZER_LINUXSLL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_LINUX_SLL2, PacketAnalyzer::ANALYZER_LINUXSLL2);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_NFLOG, PacketAnalyzer::ANALYZER_NFLOG);
	}
