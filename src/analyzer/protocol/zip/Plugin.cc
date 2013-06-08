
#include "plugin/Plugin.h"

#include "ZIP.h"

BRO_PLUGIN_BEGIN(Bro, ZIP)
	BRO_PLUGIN_DESCRIPTION("Generic ZIP support analyzer");
	BRO_PLUGIN_ANALYZER_BARE("ZIP");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
