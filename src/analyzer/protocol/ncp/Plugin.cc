
#include "plugin/Plugin.h"

#include "NCP.h"

BRO_PLUGIN_BEGIN(Bro, NCP)
	BRO_PLUGIN_DESCRIPTION("NCP analyzer");
	BRO_PLUGIN_ANALYZER("NCP", ncp::NCP_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_NCP");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
