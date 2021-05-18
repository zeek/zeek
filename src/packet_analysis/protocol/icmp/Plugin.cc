// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/icmp/ICMP.h"
#include "zeek/analyzer/Component.h"

namespace zeek::plugin::Zeek_ICMP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("ICMP",
		                 zeek::packet_analysis::ICMP::ICMPAnalyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("ICMP",
		                 zeek::packet_analysis::ICMP::ICMPSessionAdapter::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ICMP";
		config.description = "Packet analyzer for ICMP";
		return config;
		}

} plugin;

}
