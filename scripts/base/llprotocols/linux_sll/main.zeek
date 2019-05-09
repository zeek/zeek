module LL_LINUX_SLL;

const DLT_LINUX_SLL : count = 113;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_LINUX_SLL, $analyzer=LLAnalyzer::LLANALYZER_LINUXSLL),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLL, $identifier=0x0800, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLL, $identifier=0x86DD, $analyzer=LLAnalyzer::LLANALYZER_IPV6),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLL, $identifier=0x0806, $analyzer=LLAnalyzer::LLANALYZER_ARP),
	# RARP
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_LINUXSLL, $identifier=0x8035, $analyzer=LLAnalyzer::LLANALYZER_ARP)
};
