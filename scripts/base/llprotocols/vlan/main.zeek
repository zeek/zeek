module LL_VLAN;

redef LLAnalyzer::config_map += {
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x8847, $analyzer=LLAnalyzer::LLANALYZER_MPLS),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARP),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARP),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x8100, $analyzer=LLAnalyzer::LLANALYZER_VLAN),
   LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_VLAN, $identifier=0x8864, $analyzer=LLAnalyzer::LLANALYZER_PPPOE)
};
