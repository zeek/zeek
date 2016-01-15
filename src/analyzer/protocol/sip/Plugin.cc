// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SIP.h"
#include "SIP_TCP.h"

namespace plugin {
namespace Bro_SIP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SIP", ::analyzer::SIP::SIP_Analyzer::Instantiate));

		// We don't fully support SIP-over-TCP yet, so we don't activate this component.
		// AddComponent(new ::analyzer::Component("SIP_TCP", ::analyzer::sip_tcp::SIP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SIP";
		config.description = "SIP analyzer UDP-only";
		return config;
		}
} plugin;

}
}
