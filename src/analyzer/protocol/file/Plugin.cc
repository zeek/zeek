
#include "plugin/Plugin.h"

#include "./File.h"

BRO_PLUGIN_BEGIN(Bro, File)
	BRO_PLUGIN_DESCRIPTION("Generic file analyzer");
	BRO_PLUGIN_ANALYZER("FTP_Data", file::FTP_Data);
	BRO_PLUGIN_ANALYZER("IRC_Data", file::IRC_Data);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
