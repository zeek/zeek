// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SteppingStone.h"

namespace plugin {
namespace Bro_SteppingStone {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SteppingStone", ::analyzer::stepping_stone::SteppingStone_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SteppingStone";
		config.description = "Stepping stone analyzer";
		return config;
		}
} plugin;

}
}
