module LL_IEEE802_11_RADIO;

const DLT_IEEE802_11_RADIO : count = 127;
const DLT_IEEE802_11 : count = 105;

redef LLAnalyzer::config_map += {
	LLAnalyzer::ConfigEntry($identifier=DLT_IEEE802_11_RADIO, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11_RADIO),
	LLAnalyzer::ConfigEntry($parent=LLAnalyzer::LLANALYZER_IEEE802_11_RADIO, $identifier=DLT_IEEE802_11, $analyzer=LLAnalyzer::LLANALYZER_IEEE802_11)
};
