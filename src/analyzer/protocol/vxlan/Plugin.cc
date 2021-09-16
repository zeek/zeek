// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/vxlan/VXLAN.h"

namespace zeek::plugin::detail::Zeek_VXLAN
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"VXLAN", zeek::analyzer::vxlan::VXLAN_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::VXLAN";
		config.description = "VXLAN analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_VXLAN
