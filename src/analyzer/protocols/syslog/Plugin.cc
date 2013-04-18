
#include "plugin/Plugin.h"

#include "Syslog.h"

BRO_PLUGIN_BEGIN(Syslog)
	BRO_PLUGIN_DESCRIPTION("Syslog Analyzer (UDP-only currently)");
	BRO_PLUGIN_ANALYZER("SYSLOG", syslog::Syslog_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
