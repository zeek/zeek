#include "plugin/Plugin.h"

#include "Extract.h"

BRO_PLUGIN_BEGIN(Bro, FileExtract)
	BRO_PLUGIN_DESCRIPTION("Extract file content to local file system");
	BRO_PLUGIN_FILE_ANALYZER("EXTRACT", Extract);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
