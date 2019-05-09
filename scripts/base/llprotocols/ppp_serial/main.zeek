module LL_PPP_SERIAL;

const DLT_PPP_SERIAL : count = 50;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_PPP_SERIAL, $analyzer=LLAnalyzer::LLANALYZER_PPPSERIAL),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPSERIAL, $identifier=0x0281, $analyzer=LLAnalyzer::LLANALYZER_MPLS),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPSERIAL, $identifier=0x0021, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_PPPSERIAL, $identifier=0x0057, $analyzer=LLAnalyzer::LLANALYZER_IPV6)
};
