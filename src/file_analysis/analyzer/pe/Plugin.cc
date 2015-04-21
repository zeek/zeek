// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "PE.h"

namespace plugin {
namespace Bro_PE {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("PE", ::file_analysis::PE::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::PE";
		config.description = "Portable Executable analyzer";
		return config;
		}
} plugin;

}
}
