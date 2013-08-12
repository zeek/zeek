
#include "plugin/Plugin.h"

#include "ConnSize.h"

BRO_PLUGIN_BEGIN(Bro, ConnSize)
	BRO_PLUGIN_DESCRIPTION("Connection size analyzer");
	BRO_PLUGIN_ANALYZER("ConnSize", conn_size::ConnSize_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
