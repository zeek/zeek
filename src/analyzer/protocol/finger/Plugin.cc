
#include "plugin/Plugin.h"

#include "Finger.h"

BRO_PLUGIN_BEGIN(Bro, Finger)
	BRO_PLUGIN_DESCRIPTION("Finger analyzer");
	BRO_PLUGIN_ANALYZER("Finger", finger::Finger_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
