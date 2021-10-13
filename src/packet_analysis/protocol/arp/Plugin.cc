// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/arp/ARP.h"

namespace zeek::plugin::Zeek_ARP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"ARP", zeek::packet_analysis::ARP::ARPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ARP";
		config.description = "ARP packet analyzer";
		return config;
		}

	} plugin;

	}
