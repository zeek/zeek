
#include "plugin/Plugin.h"

#include "ICMP.h"

BRO_PLUGIN_BEGIN(Bro, ICMP)
	BRO_PLUGIN_DESCRIPTION("ICMP analyzer");
	BRO_PLUGIN_ANALYZER("ICMP", icmp::ICMP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
