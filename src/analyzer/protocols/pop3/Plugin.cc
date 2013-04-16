
#include "plugin/Plugin.h"

#include "POP3.h"

BRO_PLUGIN_BEGIN(POP3)
	BRO_PLUGIN_DESCRIPTION("POP3 Analyzer");
	BRO_PLUGIN_ANALYZER("POP3", POP3_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
