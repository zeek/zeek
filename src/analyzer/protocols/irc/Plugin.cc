
#include "plugin/Plugin.h"

#include "IRC.h"

BRO_PLUGIN_BEGIN(IRC)
	BRO_PLUGIN_DESCRIPTION("IRC Analyzer");
	BRO_PLUGIN_ANALYZER("IRC", IRC_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
