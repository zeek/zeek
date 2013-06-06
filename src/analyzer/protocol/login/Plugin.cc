
#include "plugin/Plugin.h"

#include "Login.h"
#include "Telnet.h"
#include "RSH.h"
#include "Rlogin.h"

BRO_PLUGIN_BEGIN(Bro, Login)
	BRO_PLUGIN_DESCRIPTION("Telnet/Rsh/Rlogin analyzers");
	BRO_PLUGIN_ANALYZER("Telnet", login::Telnet_Analyzer);
	BRO_PLUGIN_ANALYZER("Rsh", login::Rsh_Analyzer);
	BRO_PLUGIN_ANALYZER("Rlogin", login::Rlogin_Analyzer);
	BRO_PLUGIN_ANALYZER_BARE("NVT");
	BRO_PLUGIN_ANALYZER_BARE("Login");
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_Rsh");
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_Rlogin");
	BRO_PLUGIN_BIF_FILE(events);
	BRO_PLUGIN_BIF_FILE(functions);
BRO_PLUGIN_END
