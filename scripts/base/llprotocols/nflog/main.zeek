module LL_NFLOG;

const DLT_NFLOG : count = 239;
const AF_INET : count = 2;
const AF_INET6 : count = 10;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_NFLOG, $analyzer=LLAnalyzer::LLANALYZER_NFLOG),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NFLOG, $identifier=AF_INET, $analyzer=LLAnalyzer::LLANALYZER_IPV4),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_NFLOG, $identifier=AF_INET6, $analyzer=LLAnalyzer::LLANALYZER_IPV6)
};
