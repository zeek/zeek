
#include "plugin/Plugin.h"

#include "PIA.h"

BRO_PLUGIN_BEGIN(PIA)
	BRO_PLUGIN_DESCRIPTION("Protocol Identificatin Analyzers");
	BRO_PLUGIN_ANALYZER("PIA_TCP", PIA_TCP::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("PIA_UDP", PIA_UDP::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
