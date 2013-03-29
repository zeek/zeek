
#include "plugin/Plugin.h"

#include "SSL.h"

BRO_PLUGIN_BEGIN(SSL)
	BRO_PLUGIN_DESCRIPTION = "SSL Analyzer";
	BRO_PLUGIN_ANALYZER("SSL", SSL_Analyzer::InstantiateAnalyzer, true, false);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
