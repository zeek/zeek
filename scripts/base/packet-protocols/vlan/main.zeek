module LL_VLAN;

redef PacketAnalyzer::config_map += {
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x8847, $analyzer=PacketAnalyzer::ANALYZER_MPLS),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x0800, $analyzer=PacketAnalyzer::ANALYZER_IPV4),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x86DD, $analyzer=PacketAnalyzer::ANALYZER_IPV6),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x0806, $analyzer=PacketAnalyzer::ANALYZER_ARP),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x8035, $analyzer=PacketAnalyzer::ANALYZER_ARP),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x8100, $analyzer=PacketAnalyzer::ANALYZER_VLAN),
   PacketAnalyzer::ConfigEntry($parent=PacketAnalyzer::ANALYZER_VLAN, $identifier=0x8864, $analyzer=PacketAnalyzer::ANALYZER_PPPOE)
};
