// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "PIA.h"

namespace plugin {
namespace Bro_PIA {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("PIA_TCP", ::analyzer::pia::PIA_TCP::Instantiate));
		AddComponent(new ::analyzer::Component("PIA_UDP", ::analyzer::pia::PIA_UDP::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::PIA";
		config.description = "Analyzers implementing Dynamic Protocol";
		return config;
		}
} plugin;

}
}
