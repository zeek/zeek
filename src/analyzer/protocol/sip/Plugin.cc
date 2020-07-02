// See the file  in the main distribution directory for copyright.

#include "SIP.h"
#include "SIP_TCP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SIP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SIP", ::analyzer::SIP::SIP_Analyzer::Instantiate));

		// We don't fully support SIP-over-TCP yet, so we don't activate this component.
		// AddComponent(new zeek::analyzer::Component("SIP_TCP", ::analyzer::sip_tcp::SIP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SIP";
		config.description = "SIP analyzer UDP-only";
		return config;
		}
} plugin;

}
}
