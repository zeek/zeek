module PacketAnalyzer::NULL;

const DLT_NULL : count = 0;
const AF_INET : count = 2;
const AF_INET6 : count = 10;

redef PacketAnalyzer::config_map += {
	PacketAnalyzer::ConfigEntry($identifier=DLT_NULL, $analyzer=PacketAnalyzer::ANALYZER_NULL),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NULL, $identifier=AF_INET, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
	
	## From the Wireshark Wiki: AF_INET6ANALYZER, unfortunately, has different values in
	## {NetBSD,OpenBSD,BSD/OS}, {FreeBSD,DragonFlyBSD}, and {Darwin/Mac OS X}, so an IPv6
	## packet might have a link-layer header with 24, 28, or 30 as the AF_ value. As we
	## may be reading traces captured on platforms other than what we're running on, we
	## accept them all here.
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NULL, $identifier=24, $analyzer=PacketAnalyzer::ANALYZER_IPV6),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NULL, $identifier=28, $analyzer=PacketAnalyzer::ANALYZER_IPV6),
	PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_NULL, $identifier=30, $analyzer=PacketAnalyzer::ANALYZER_IPV6)
};
