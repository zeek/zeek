
#include "plugin/Plugin.h"

#include "Teredo.h"

BRO_PLUGIN_BEGIN(Bro, Teredo)
	BRO_PLUGIN_DESCRIPTION("Teredo analyzer");
	BRO_PLUGIN_ANALYZER("Teredo", teredo::Teredo_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
