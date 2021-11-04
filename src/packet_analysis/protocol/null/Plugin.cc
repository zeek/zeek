// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/null/Null.h"

namespace zeek::plugin::Zeek_Null
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"Null", zeek::packet_analysis::Null::NullAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Null";
		config.description = "Null packet analyzer";
		return config;
		}

	} plugin;

	}
