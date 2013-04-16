
#include "plugin/Plugin.h"

#include "ICMP.h"

BRO_PLUGIN_BEGIN(ICMP)
	BRO_PLUGIN_DESCRIPTION("ICMP Analyzer");
	BRO_PLUGIN_ANALYZER("ICMP", ICMP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
