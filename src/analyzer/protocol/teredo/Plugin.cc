// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Teredo.h"

namespace plugin {
namespace Bro_Teredo {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Teredo", ::analyzer::teredo::Teredo_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Teredo";
		config.description = "Teredo analyzer";
		return config;
		}
} plugin;

}
}
