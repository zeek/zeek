// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "ZIP.h"

namespace plugin {
namespace Bro_ZIP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("ZIP", 0));

		plugin::Configuration config;
		config.name = "Bro::ZIP";
		config.description = "Generic ZIP support analyzer";
		return config;
		}
} plugin;

}
}
