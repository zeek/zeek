
#include "plugin/Plugin.h"

#include "BackDoor.h"

BRO_PLUGIN_BEGIN(Bro, BackDoor)
	BRO_PLUGIN_DESCRIPTION("Backdoor Analyzer (deprecated)");
	BRO_PLUGIN_ANALYZER("BackDoor", backdoor::BackDoor_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
