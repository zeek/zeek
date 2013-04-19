
#include "plugin/Plugin.h"

#include "Teredo.h"

BRO_PLUGIN_BEGIN(Teredo)
	BRO_PLUGIN_DESCRIPTION("Teredo Analyzer");
	BRO_PLUGIN_ANALYZER("TEREDO", teredo::Teredo_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
