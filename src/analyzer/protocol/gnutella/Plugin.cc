// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Gnutella.h"

namespace plugin {
namespace Bro_Gnutella {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Gnutella", ::analyzer::gnutella::Gnutella_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Gnutella";
		config.description = "Gnutella analyzer";
		return config;
		}
} plugin;

}
}
