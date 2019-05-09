module LL_ETHERNET;

const DLT_EN10MB : count = 1;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_EN10MB, $analyzer=LLAnalyzer::LLANALYZER_ETHERNET),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x8847, $analyzer=LLAnalyzer::LLANALYZER_MPLS),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARP),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARP),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x8100, $analyzer=LLAnalyzer::LLANALYZER_VLAN),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x88A8, $analyzer=LLAnalyzer::LLANALYZER_VLAN),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x9100, $analyzer=LLAnalyzer::LLANALYZER_VLAN),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_ETHERNET, $identifier=0x8864, $analyzer=LLAnalyzer::LLANALYZER_PPPOE)
};
