
#include "plugin/Plugin.h"

#include "SIP.h"

BRO_PLUGIN_BEGIN(Bro, SIP)
	BRO_PLUGIN_DESCRIPTION("Session Initiation Protocol Analyzer (UDP-only currently)");
	BRO_PLUGIN_ANALYZER("SIP", sip::SIP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
