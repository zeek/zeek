
#include "plugin/Plugin.h"

#include "SteppingStone.h"

BRO_PLUGIN_BEGIN(Bro, SteppingStone)
	BRO_PLUGIN_DESCRIPTION("Stepping stone analyzer (deprecated)");
	BRO_PLUGIN_ANALYZER("SteppingStone", stepping_stone::SteppingStone_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
