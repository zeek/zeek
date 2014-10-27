// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "AYIYA.h"

namespace plugin {
namespace Bro_AYIYA {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("AYIYA", ::analyzer::ayiya::AYIYA_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::AYIYA";
		config.description = "AYIYA Analyzer";
		return config;
		}
} plugin;

}
}
