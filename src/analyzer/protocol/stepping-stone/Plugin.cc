
#include "plugin/Plugin.h"

#include "SteppingStone.h"

BRO_PLUGIN_BEGIN(SteppingStone)
	BRO_PLUGIN_DESCRIPTION("SteppingStone Analyzer (deprecated)");
	BRO_PLUGIN_ANALYZER("STEPPINGSTONE", stepping_stone::SteppingStone_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
