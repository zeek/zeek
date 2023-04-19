// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/snap/SNAP.h"

namespace zeek::plugin::Zeek_SNAP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"SNAP", zeek::packet_analysis::SNAP::SNAPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SNAP";
		config.description = "SNAP packet analyzer";
		return config;
		}

	} plugin;

	}
