
#include "plugin/Plugin.h"

#include "TCP.h"

BRO_PLUGIN_BEGIN(TCP)
	BRO_PLUGIN_DESCRIPTION("TCP Analyzer");
	BRO_PLUGIN_ANALYZER("TCP", TCP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("TCPStats", TCPStats_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("ContentLine");
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
