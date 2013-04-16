
#include "plugin/Plugin.h"

#include "ZIP.h"

BRO_PLUGIN_BEGIN(ZIP)
	BRO_PLUGIN_DESCRIPTION("Generic ZIP support analyzer");
	BRO_PLUGIN_ANALYZER("ZIP", 0);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
