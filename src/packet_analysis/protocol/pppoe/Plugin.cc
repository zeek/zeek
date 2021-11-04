// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/pppoe/PPPoE.h"

namespace zeek::plugin::Zeek_PPPoE
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"PPPoE", zeek::packet_analysis::PPPoE::PPPoEAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::PPPoE";
		config.description = "PPPoE packet analyzer";
		return config;
		}

	} plugin;

	}
