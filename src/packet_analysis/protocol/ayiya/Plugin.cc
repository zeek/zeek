// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ayiya/AYIYA.h"

namespace zeek::plugin::Zeek_AYIYA
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"AYIYA", zeek::packet_analysis::AYIYA::AYIYAAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AYIYA";
		config.description = "AYIYA packet analyzer";
		return config;
		}

	} plugin;

	}
