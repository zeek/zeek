module PacketAnalyzer::MPLS;

redef PacketAnalyzer::config_map += {
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_MPLS, $analyzer=PacketAnalyzer::ANALYZER_IP)
};
