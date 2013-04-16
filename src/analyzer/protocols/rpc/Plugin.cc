
#include "plugin/Plugin.h"

#include "RPC.h"
#include "NFS.h"
#include "Portmap.h"

BRO_PLUGIN_BEGIN(RPC)
	BRO_PLUGIN_DESCRIPTION("Analyzers for RPC-based protocols");
	BRO_PLUGIN_ANALYZER("NFS", NFS_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_ANALYZER("PORTMAPPER", Portmapper_Analyzer::InstantiateAnalyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_RPC");
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_NFS");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
