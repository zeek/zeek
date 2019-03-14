// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "VXLAN.h"

namespace plugin {
namespace Bro_VXLAN {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("VXLAN", ::analyzer::vxlan::VXLAN_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::VXLAN";
		config.description = "VXLAN analyzer";
		return config;
		}
} plugin;

}
}
