##! Implements base functionality for IGMP analysis.

module IGMP;

event zeek_init() &priority=5
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x02, "IGMP") )
		{
		Reporter::error("Failed to register IGMP Spicy analyzer.");
		}
	}
