// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"

namespace zeek::plugin::Zeek_VXLAN
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"VXLAN", zeek::packet_analysis::VXLAN::VXLAN_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::VXLAN";
		config.description = "VXLAN packet analyzer";
		return config;
		}

	} plugin;

	}
