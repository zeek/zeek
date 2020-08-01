// See the file  in the main distribution directory for copyright.

#include "NetbiosSSN.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_NetBIOS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("NetbiosSSN", ::analyzer::netbios_ssn::NetbiosSSN_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_NetbiosSSN", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::NetBIOS";
		config.description = "NetBIOS analyzer support";
		return config;
		}
} plugin;

}
}
