
#include "plugin/Plugin.h"

#include "DNP3.h"

BRO_PLUGIN_BEGIN(Bro, DNP3)
	BRO_PLUGIN_DESCRIPTION("DNP3 analyzer");
	BRO_PLUGIN_ANALYZER("DNP3", dnp3::DNP3_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
