
#include "plugin/Plugin.h"

#include "AYIYA.h"

BRO_PLUGIN_BEGIN(Bro, AYIYA)
	BRO_PLUGIN_DESCRIPTION("AYIYA Analyzer");
	BRO_PLUGIN_ANALYZER("AYIYA", ayiya::AYIYA_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
