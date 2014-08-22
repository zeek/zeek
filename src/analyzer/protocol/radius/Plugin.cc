// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "RADIUS.h"

namespace plugin {
namespace Bro_RADIUS {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("RADIUS", ::analyzer::RADIUS::RADIUS_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::RADIUS";
		config.description = "RADIUS analyzer";
		return config;
		}
} plugin;

}
}
