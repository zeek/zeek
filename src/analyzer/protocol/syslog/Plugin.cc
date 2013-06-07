
#include "plugin/Plugin.h"

#include "Syslog.h"

BRO_PLUGIN_BEGIN(Bro, Syslog)
	BRO_PLUGIN_DESCRIPTION("Syslog analyzer (UDP-only currently)");
	BRO_PLUGIN_ANALYZER("Syslog", syslog::Syslog_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
