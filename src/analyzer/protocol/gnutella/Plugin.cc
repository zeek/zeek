
#include "plugin/Plugin.h"

#include "Gnutella.h"

BRO_PLUGIN_BEGIN(Gnutella)
	BRO_PLUGIN_DESCRIPTION("Gnutella Analyzer");
	BRO_PLUGIN_ANALYZER("GNUTELLA", gnutella::Gnutella_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
