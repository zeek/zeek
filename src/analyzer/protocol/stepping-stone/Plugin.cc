// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/stepping-stone/SteppingStone.h"

namespace zeek::plugin::detail::Zeek_SteppingStone
{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"SteppingStone", zeek::analyzer::stepping_stone::SteppingStone_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SteppingStone";
		config.description = "Stepping stone analyzer";
		return config;
		}
	} plugin;

} // namespace zeek::plugin::detail::Zeek_SteppingStone
