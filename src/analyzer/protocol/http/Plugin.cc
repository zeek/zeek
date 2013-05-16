
#include "plugin/Plugin.h"

#include "HTTP.h"

BRO_PLUGIN_BEGIN(Bro, HTTP)
	BRO_PLUGIN_DESCRIPTION("HTTP analyzer");
	BRO_PLUGIN_ANALYZER("HTTP", http::HTTP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
