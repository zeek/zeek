// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/icmp/ICMP.h"

namespace zeek::plugin::Zeek_ICMP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("ICMP_PKT",
		                 zeek::packet_analysis::ICMP::ICMPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ICMP_PKT";
		config.description = "Packet analyzer for ICMP";
		return config;
		}

} plugin;

}
