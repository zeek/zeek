// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"

namespace zeek::plugin::Zeek_TCP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("TCP_PKT",
		                 zeek::packet_analysis::TCP::TCPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::TCP_PKT";
		config.description = "Packet analyzer for TCP";
		return config;
		}

} plugin;

}
