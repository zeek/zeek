
#include "plugin/Plugin.h"

#include "Finger.h"

BRO_PLUGIN_BEGIN(Finger)
	BRO_PLUGIN_DESCRIPTION("Finger Analyzer");
	BRO_PLUGIN_ANALYZER("FINGER", finger::Finger_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
