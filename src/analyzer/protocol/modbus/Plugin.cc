// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Modbus.h"

namespace plugin {
namespace Bro_Modbus {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("MODBUS", ::analyzer::modbus::ModbusTCP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Modbus";
		config.description = "Modbus analyzer";
		return config;
		}
} plugin;

}
}
