
#include "plugin/Plugin.h"

#include "Ident.h"

BRO_PLUGIN_BEGIN(Ident)
	BRO_PLUGIN_DESCRIPTION("Ident Analyzer");
	BRO_PLUGIN_ANALYZER("IDENT", ident::Ident_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
