// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "NTLM.h"

namespace plugin {
namespace Zeek_NTLM {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("NTLM", ::analyzer::ntlm::NTLM_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::NTLM";
		config.description = "NTLM analyzer";
		return config;
		}
} plugin;

}
}
