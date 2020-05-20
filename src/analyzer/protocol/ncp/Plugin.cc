// See the file  in the main distribution directory for copyright.

#include "NCP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_NCP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("NCP", ::analyzer::ncp::NCP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_NCP", nullptr));

		plugin::Configuration config;
		config.name = "Zeek::NCP";
		config.description = "NCP analyzer";
		return config;
		}
} plugin;

}
}
