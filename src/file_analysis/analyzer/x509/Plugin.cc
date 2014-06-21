#include "plugin/Plugin.h"

#include "X509.h"

BRO_PLUGIN_BEGIN(Bro, X509)
	BRO_PLUGIN_DESCRIPTION("X509 certificate parser");
	BRO_PLUGIN_FILE_ANALYZER("X509", X509);
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(types);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
