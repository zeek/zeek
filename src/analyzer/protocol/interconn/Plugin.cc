
#include "plugin/Plugin.h"

#include "InterConn.h"

BRO_PLUGIN_BEGIN(Bro, InterConn)
	BRO_PLUGIN_DESCRIPTION("InterConn analyzer (deprecated)");
	BRO_PLUGIN_ANALYZER("InterConn", interconn::InterConn_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
