
#include "plugin/Plugin.h"

#include "SMB.h"

BRO_PLUGIN_BEGIN(SMB)
	BRO_PLUGIN_DESCRIPTION("SMB Analyzer");
	BRO_PLUGIN_ANALYZER("SMB", SMB_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_SMB");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
