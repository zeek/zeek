
#include "plugin/Plugin.h"

#include "SSH.h"

BRO_PLUGIN_BEGIN(SSH)
	BRO_PLUGIN_DESCRIPTION("SSH Analyzer");
	BRO_PLUGIN_ANALYZER("SSH", SSH_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
