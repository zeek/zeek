
#include "plugin/Plugin.h"

#include "FTP.h"

BRO_PLUGIN_BEGIN(FTP)
	BRO_PLUGIN_DESCRIPTION("FTP Analyzer");
	BRO_PLUGIN_ANALYZER("FTP", FTP_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("FTP_ADAT");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
