// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/gre/GRE.h"

namespace zeek::plugin::Zeek_GRE
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"GRE", zeek::packet_analysis::GRE::GREAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::GRE";
		config.description = "GRE packet analyzer";
		return config;
		}

	} plugin;

	}
