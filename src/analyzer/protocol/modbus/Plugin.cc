
#include "plugin/Plugin.h"

#include "Modbus.h"

BRO_PLUGIN_BEGIN(Bro, Modbus)
	BRO_PLUGIN_DESCRIPTION("Modbus analyzer");
	BRO_PLUGIN_ANALYZER("MODBUS", modbus::ModbusTCP_Analyzer);
	BRO_PLUGIN_BIF_FILE(events);
BRO_PLUGIN_END
