module PacketAnalyzer::IP;

const IPPROTO_TCP : count = 6;
const IPPROTO_UDP : count = 17;
const IPPROTO_ICMP : count = 1;
const IPPROTO_ICMP6 : count = 58;

const IPPROTO_IPIP : count = 4;
const IPPROTO_IPV6 : count = 41;
const IPPROTO_GRE : count = 47;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_IPIP, PacketAnalyzer::ANALYZER_IPTUNNEL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_IPV6, PacketAnalyzer::ANALYZER_IPTUNNEL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_GRE, PacketAnalyzer::ANALYZER_GRE);

	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_TCP, PacketAnalyzer::ANALYZER_TCP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_UDP, PacketAnalyzer::ANALYZER_UDP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_ICMP, PacketAnalyzer::ANALYZER_ICMP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, IPPROTO_ICMP6, PacketAnalyzer::ANALYZER_ICMP);
	}
