// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SOCKS.h"

namespace plugin {
namespace Bro_SOCKS {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SOCKS", ::analyzer::socks::SOCKS_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SOCKS";
		config.description = "SOCKS analyzer";
		return config;
		}
} plugin;

}
}
