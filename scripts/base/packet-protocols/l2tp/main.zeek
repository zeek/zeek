module PacketAnalyzer::L2TP;

export {
	## Default analyzer
	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_PPP &redef;

	## The set of UDP ports used for L2TP tunnels.
	const l2tp_ports = { 1701/udp } &redef;

	## The amount of time between attempts to expire V3 session state.
	const v3_state_timer_interval = 5min &redef;

	## The maximum age before a V3 session will be timed out.
	const v3_session_max_age = 2min &redef;

	## The maximum size of the v3 session map. If this limit is exceeded a
	## `l2tp_max_v3_sessions_exceeded` weird will be emitted and further sessions will
	## be dropped. Setting this to zero disables the limit.
	const v3_max_sessions: count = 4000 &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_L2TP, l2tp_ports);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_L2TP, 0x05, PacketAnalyzer::ANALYZER_ETHERNET);
	}
