// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/analyzer/Component.h"

namespace zeek::plugin::Zeek_TCP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("TCP",
		                 zeek::packet_analysis::TCP::TCPAnalyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("TCP",
		                 zeek::packet_analysis::TCP::TCPSessionAdapter::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::TCP_PKT";
		config.description = "Packet analyzer for TCP";
		return config;
		}

} plugin;

}
