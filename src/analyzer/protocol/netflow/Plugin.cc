
#include "plugin/Plugin.h"

BRO_PLUGIN_BEGIN(Bro, NetFlow)
	BRO_PLUGIN_DESCRIPTION("NetFlow parsing code");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
