
#include "plugin/Plugin.h"

#include "PIA.h"

BRO_PLUGIN_BEGIN(PIA)
	BRO_PLUGIN_DESCRIPTION("Protocol Identificatin Analyzers");
	BRO_PLUGIN_ANALYZER("PIA_TCP", pia::PIA_TCP);
	BRO_PLUGIN_ANALYZER("PIA_UDP", pia::PIA_UDP);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
