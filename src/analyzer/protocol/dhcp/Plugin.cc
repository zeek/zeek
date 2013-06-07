
#include "plugin/Plugin.h"

#include "DHCP.h"

BRO_PLUGIN_BEGIN(Bro, DHCP)
	BRO_PLUGIN_DESCRIPTION("DHCP analyzer");
	BRO_PLUGIN_ANALYZER("DHCP", dhcp::DHCP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
