// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "NCP.h"

namespace plugin {
namespace Bro_NCP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("NCP", ::analyzer::ncp::NCP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_NCP", 0));

		plugin::Configuration config;
		config.name = "Bro::NCP";
		config.description = "NCP analyzer";
		return config;
		}
} plugin;

}
}
