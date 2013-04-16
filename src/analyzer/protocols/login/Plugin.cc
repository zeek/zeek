
#include "plugin/Plugin.h"

#include "Login.h"
#include "Telnet.h"
#include "RSH.h"
#include "Rlogin.h"

BRO_PLUGIN_BEGIN(Login)
	BRO_PLUGIN_DESCRIPTION("Telnet/Rsh/Rlogin Analyzer");
	BRO_PLUGIN_ANALYZER("TELNET", Telnet_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("RSH", Rsh_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("RLOGIN", Rlogin_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("NVT", 0);
	BRO_PLUGIN_ANALYZER("Login", 0);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_Rsh");
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_Rlogin");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
