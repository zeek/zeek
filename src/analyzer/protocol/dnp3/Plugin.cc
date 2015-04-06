// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DNP3.h"

namespace plugin {
namespace Bro_DNP3 {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("DNP3_TCP", ::analyzer::dnp3::DNP3_TCP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("DNP3_UDP", ::analyzer::dnp3::DNP3_UDP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::DNP3";
		config.description = "DNP3 UDP/TCP analyzers";
		return config;
		}
} plugin;

}
}
