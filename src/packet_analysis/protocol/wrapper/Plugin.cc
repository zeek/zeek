// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/wrapper/Wrapper.h"

namespace zeek::plugin::Zeek_Wrapper
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"Wrapper", zeek::packet_analysis::Wrapper::WrapperAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Wrapper";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

	} plugin;

	}
