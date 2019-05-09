module LL_IEEE802_11;

const DLT_IEEE802_11 : count = 105;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_IEEE802_11, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARP),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARP)
};
