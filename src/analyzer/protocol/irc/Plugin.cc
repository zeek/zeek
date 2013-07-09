
#include "plugin/Plugin.h"

#include "IRC.h"

BRO_PLUGIN_BEGIN(Bro, IRC)
	BRO_PLUGIN_DESCRIPTION("IRC analyzer");
	BRO_PLUGIN_ANALYZER("IRC", irc::IRC_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
