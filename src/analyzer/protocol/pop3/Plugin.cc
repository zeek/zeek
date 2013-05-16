
#include "plugin/Plugin.h"

#include "POP3.h"

BRO_PLUGIN_BEGIN(Bro, POP3)
	BRO_PLUGIN_DESCRIPTION("POP3 analyzer");
	BRO_PLUGIN_ANALYZER("POP3", pop3::POP3_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
