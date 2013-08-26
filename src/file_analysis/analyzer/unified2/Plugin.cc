// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Unified2.h"

BRO_PLUGIN_BEGIN(Bro, Unified2)
	BRO_PLUGIN_DESCRIPTION("Analyze Unified2 alert files.");
	BRO_PLUGIN_FILE_ANALYZER("UNIFIED2", Unified2);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(types);
BRO_PLUGIN_END
