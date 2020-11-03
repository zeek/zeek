// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/udp/UDP.h"

namespace zeek::plugin::detail::Zeek_UDP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("UDP", zeek::analyzer::udp::UDP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::UDP";
		config.description = "UDP Analyzer";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_UDP
