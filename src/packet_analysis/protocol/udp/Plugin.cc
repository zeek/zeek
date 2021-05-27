// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/udp/UDP.h"
#include "zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h"
#include "zeek/analyzer/Component.h"

namespace zeek::plugin::Zeek_UDP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("UDP",
		                 zeek::packet_analysis::UDP::UDPAnalyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("UDP",
		                 zeek::packet_analysis::UDP::UDPSessionAdapter::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::UDP";
		config.description = "Packet analyzer for UDP";
		return config;
		}

} plugin;

}
