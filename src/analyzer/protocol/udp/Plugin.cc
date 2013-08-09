
#include "plugin/Plugin.h"

#include "analyzer/protocol/udp/UDP.h"

BRO_PLUGIN_BEGIN(Bro, UDP)
	BRO_PLUGIN_DESCRIPTION("UDP Analyzer");
	BRO_PLUGIN_ANALYZER("UDP", udp::UDP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
