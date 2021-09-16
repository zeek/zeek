// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"

namespace zeek::plugin::Zeek_IP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"IP", zeek::packet_analysis::IP::IPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IP";
		config.description = "Packet analyzer for IP fallback (v4 or v6)";
		return config;
		}

	} plugin;

	}
