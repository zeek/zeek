// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/root/Root.h"

namespace zeek::plugin::Zeek_Root
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"Root", zeek::packet_analysis::Root::RootAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Root";
		config.description = "Root packet analyzer";
		return config;
		}

	} plugin;

	}
