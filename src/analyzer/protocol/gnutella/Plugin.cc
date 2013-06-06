
#include "plugin/Plugin.h"

#include "Gnutella.h"

BRO_PLUGIN_BEGIN(Bro, Gnutella)
	BRO_PLUGIN_DESCRIPTION("Gnutella analyzer");
	BRO_PLUGIN_ANALYZER("Gnutella", gnutella::Gnutella_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
