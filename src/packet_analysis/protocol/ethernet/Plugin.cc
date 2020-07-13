// See the file "COPYING" in the main distribution directory for copyright.

#include "Ethernet.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_Ethernet {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("Ethernet",
		                 zeek::packet_analysis::Ethernet::EthernetAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Ethernet";
		config.description = "Ethernet packet analyzer";
		return config;
		}

} plugin;

}
