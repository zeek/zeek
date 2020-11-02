module PacketAnalyzer::NULL;

const DLT_NULL : count = 0;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_NULL, PacketAnalyzer::ANALYZER_NULL);

	# From the Wireshark Wiki: AF_INET6ANALYZER, unfortunately, has different
	# values in {NetBSD,OpenBSD,BSD/OS}, {FreeBSD,DragonFlyBSD}, and
	# {Darwin/macOS}, so an IPv6 packet might have a link-layer header with 24, 28,
	# or 30 as the ``AF_`` value. As we may be reading traces captured on platforms
	# other than what we're running on, we accept them all here.
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 2, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 24, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 28, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 30, PacketAnalyzer::ANALYZER_IP);
	}
