#include "plugin/Plugin.h"

#include "MySQL.h"

BRO_PLUGIN_BEGIN(Bro, MySQL)
	BRO_PLUGIN_DESCRIPTION("MySQL analyzer");
	BRO_PLUGIN_ANALYZER("MySQL", MySQL::MySQL_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
