
#include "plugin/Plugin.h"

#include "InterConn.h"

BRO_PLUGIN_BEGIN(InterConn)
	BRO_PLUGIN_DESCRIPTION("InterConn Analyzer (deprecated)");
	BRO_PLUGIN_ANALYZER("INTERCONN", interconn::InterConn_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
