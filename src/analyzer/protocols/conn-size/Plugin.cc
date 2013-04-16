
#include "plugin/Plugin.h"

#include "ConnSize.h"

BRO_PLUGIN_BEGIN(ConnSize)
	BRO_PLUGIN_DESCRIPTION("Connection size analyzer");
	BRO_PLUGIN_ANALYZER("CONNSIZE", ConnSize_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
