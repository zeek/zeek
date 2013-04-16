
#include "plugin/Plugin.h"

#include "HTTP.h"

BRO_PLUGIN_BEGIN(HTTP)
	BRO_PLUGIN_DESCRIPTION("HTTP Analyzer");
	BRO_PLUGIN_ANALYZER("HTTP", HTTP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
