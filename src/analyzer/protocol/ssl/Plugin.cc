
#include "plugin/Plugin.h"

#include "SSL.h"

BRO_PLUGIN_BEGIN(Bro, SSL)
	BRO_PLUGIN_DESCRIPTION("SSL analyzer");
	BRO_PLUGIN_ANALYZER("SSL", ssl::SSL_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
