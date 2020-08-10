// See the file  in the main distribution directory for copyright.

#include "Modbus.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace zeek::plugin::detail::Zeek_Modbus {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("MODBUS", zeek::analyzer::modbus::ModbusTCP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Modbus";
		config.description = "Modbus analyzer";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_Modbus
