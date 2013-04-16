
#include "plugin/Plugin.h"

#include "DHCP.h"

BRO_PLUGIN_BEGIN(DHCP)
	BRO_PLUGIN_DESCRIPTION("DHCP Analyzer");
	BRO_PLUGIN_ANALYZER("DHCP", DHCP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
