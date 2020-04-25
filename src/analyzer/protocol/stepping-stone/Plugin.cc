// See the file  in the main distribution directory for copyright.

#include "SteppingStone.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SteppingStone {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("SteppingStone", ::analyzer::stepping_stone::SteppingStone_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::SteppingStone";
		config.description = "Stepping stone analyzer";
		return config;
		}
} plugin;

}
}
