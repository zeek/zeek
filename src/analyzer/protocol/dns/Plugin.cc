
#include "plugin/Plugin.h"

#include "DNS.h"

BRO_PLUGIN_BEGIN(DNS)
	BRO_PLUGIN_DESCRIPTION("DNS analyzer");
	BRO_PLUGIN_ANALYZER("DNS", dns::DNS_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_DNS");
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
