// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "ZIP_File.h"

BRO_PLUGIN_BEGIN(Bro, ZIP_File)
	BRO_PLUGIN_DESCRIPTION("Analyze ZIP files.");
	BRO_PLUGIN_FILE_ANALYZER("ZIP_FILE", ZIP_File);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(types);
BRO_PLUGIN_END
