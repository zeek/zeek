
#include "plugin/Plugin.h"

#include "NetbiosSSN.h"

BRO_PLUGIN_BEGIN(Bro, NetBIOS)
	BRO_PLUGIN_DESCRIPTION("NetBIOS analyzer (support only SSN currently)");
	BRO_PLUGIN_ANALYZER("NetbiosSSN", netbios_ssn::NetbiosSSN_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_NetbiosSSN");
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
