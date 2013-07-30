
#include "plugin/Plugin.h"

#include "SSH.h"

BRO_PLUGIN_BEGIN(Bro, SSH)
	BRO_PLUGIN_DESCRIPTION("SSH analyzer");
	BRO_PLUGIN_ANALYZER("SSH", ssh::SSH_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
