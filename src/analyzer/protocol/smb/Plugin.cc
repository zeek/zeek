
#include "plugin/Plugin.h"

#include "SMB.h"

BRO_PLUGIN_BEGIN(Bro, SMB)
	BRO_PLUGIN_DESCRIPTION("SMB analyzer");
	BRO_PLUGIN_ANALYZER("SMB", smb::SMB_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_SMB");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
