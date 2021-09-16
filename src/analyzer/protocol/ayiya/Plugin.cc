// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/ayiya/AYIYA.h"

namespace zeek::plugin::detail::Zeek_AYIYA
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"AYIYA", zeek::analyzer::ayiya::AYIYA_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AYIYA";
		config.description = "AYIYA Analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_AYIYA
