
#include "plugin/Plugin.h"

BRO_PLUGIN_BEGIN(Bro, MIME)
	BRO_PLUGIN_DESCRIPTION("MIME parsing code");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
