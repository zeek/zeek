// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "NetbiosSSN.h"

namespace plugin {
namespace Bro_NetBIOS {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("NetbiosSSN", ::analyzer::netbios_ssn::NetbiosSSN_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_NetbiosSSN", 0));

		plugin::Configuration config;
		config.name = "Bro::NetBIOS";
		config.description = "NetBIOS analyzer support";
		return config;
		}
} plugin;

}
}
