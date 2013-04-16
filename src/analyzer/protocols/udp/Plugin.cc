
#include "plugin/Plugin.h"

#include "analyzer/protocols/udp/UDP.h"

BRO_PLUGIN_BEGIN(UDP)
	BRO_PLUGIN_DESCRIPTION("UDP Analyzer");
	BRO_PLUGIN_ANALYZER("UDP", UDP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
