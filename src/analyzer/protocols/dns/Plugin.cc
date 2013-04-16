
#include "plugin/Plugin.h"

#include "DNS.h"

BRO_PLUGIN_BEGIN(DNS)
	BRO_PLUGIN_DESCRIPTION("DNS Analyzer");
	BRO_PLUGIN_ANALYZER("DNS", DNS_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_DNS");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
