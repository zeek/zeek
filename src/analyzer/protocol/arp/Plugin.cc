
#include "plugin/Plugin.h"

BRO_PLUGIN_BEGIN(Bro, ARP)
	BRO_PLUGIN_DESCRIPTION("ARP Parsing Code");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
