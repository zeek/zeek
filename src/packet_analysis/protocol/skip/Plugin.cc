// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/skip/Skip.h"

namespace zeek::plugin::Zeek_Skip
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"Skip", zeek::packet_analysis::Skip::SkipAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Skip";
		config.description = "Skip packet analyzer";
		return config;
		}

	} plugin;

	}
