
#include "plugin/Plugin.h"

#include "NTP.h"

BRO_PLUGIN_BEGIN(Bro, NTP)
	BRO_PLUGIN_DESCRIPTION("NTP analyzer");
	BRO_PLUGIN_ANALYZER("NTP", ntp::NTP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
