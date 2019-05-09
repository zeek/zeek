module LL_DEFAULT;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_DEFAULTANALYZER, $identifier=4, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_DEFAULTANALYZER, $identifier=6, $analyzer=LLAnalyzer::LLANALYZER_IPV6)
};
