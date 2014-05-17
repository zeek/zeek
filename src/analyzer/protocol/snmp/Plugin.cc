
#include "plugin/Plugin.h"
#include "SNMP.h"

BRO_PLUGIN_BEGIN(Bro, SNMP)
	BRO_PLUGIN_DESCRIPTION("SNMP Analyzer");
	BRO_PLUGIN_ANALYZER("SNMP", snmp::SNMP_Analyzer);
	BRO_PLUGIN_BIF_FILE(types);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
