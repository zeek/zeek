module LL_FDDI;

const DLT_FDDI : count = 10;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_FDDI, $analyzer=LLAnalyzer::LLANALYZER_FDDI)
};
