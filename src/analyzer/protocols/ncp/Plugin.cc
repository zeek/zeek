
#include "plugin/Plugin.h"

#include "NCP.h"

BRO_PLUGIN_BEGIN(NCP)
	BRO_PLUGIN_DESCRIPTION("NCP Analyzer");
	BRO_PLUGIN_ANALYZER("NCP", NCP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_NCP");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
