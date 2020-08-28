// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_Default {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("IP",
		                 zeek::packet_analysis::IP::IPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IP";
		config.description = "Packet analyzer for IP fallback (v4 or v6)";
		return config;
		}

} plugin;

}
