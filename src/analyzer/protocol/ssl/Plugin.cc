
#include "plugin/Plugin.h"

#include "SSL.h"

BRO_PLUGIN_BEGIN(SSL)
	BRO_PLUGIN_DESCRIPTION("SSL Analyzer");
	BRO_PLUGIN_ANALYZER("SSL", ssl::SSL_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
