
#include "plugin/Plugin.h"

#include "GTPv1.h"

BRO_PLUGIN_BEGIN(Bro, GTPv1)
	BRO_PLUGIN_DESCRIPTION("GTPv1 analyzer");
	BRO_PLUGIN_ANALYZER("GTPv1", gtpv1::GTPv1_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
