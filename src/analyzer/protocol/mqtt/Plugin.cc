// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "MQTT.h"

namespace plugin { 
namespace Bro_MQTT {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("MQTT",
		             ::analyzer::MQTT::MQTT_Analyzer::InstantiateAnalyzer));
		
		plugin::Configuration config;
		config.name = "Bro::MQTT";
		config.description = "Message Queuing Telemetry Transport v3.1.1 Protocol analyzer";
		return config;
		}
} plugin;

}
}
