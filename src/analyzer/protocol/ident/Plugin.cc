
#include "plugin/Plugin.h"

#include "Ident.h"

BRO_PLUGIN_BEGIN(Bro, Ident)
	BRO_PLUGIN_DESCRIPTION("Ident analyzer");
	BRO_PLUGIN_ANALYZER("Ident", ident::Ident_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
