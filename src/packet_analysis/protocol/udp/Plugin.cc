// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/udp/UDP.h"

namespace zeek::plugin::Zeek_UDP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("UDP_PKT",
		                 zeek::packet_analysis::UDP::UDPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::UDP_PKT";
		config.description = "Packet analyzer for UDP";
		return config;
		}

} plugin;

}
