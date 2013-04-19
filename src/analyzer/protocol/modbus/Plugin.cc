
#include "plugin/Plugin.h"

#include "Modbus.h"

BRO_PLUGIN_BEGIN(Modbus)
	BRO_PLUGIN_DESCRIPTION("Modbus Analyzer");
	BRO_PLUGIN_ANALYZER("MODBUS", modbus::ModbusTCP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
