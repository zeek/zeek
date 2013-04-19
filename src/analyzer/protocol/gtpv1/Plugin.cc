
#include "plugin/Plugin.h"

#include "GTPv1.h"

BRO_PLUGIN_BEGIN(GTPV1)
	BRO_PLUGIN_DESCRIPTION("GTPv1 Analyzer");
	BRO_PLUGIN_ANALYZER("GTPV1", gtpv1::GTPv1_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
