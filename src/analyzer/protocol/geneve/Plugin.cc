// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/geneve/Geneve.h"

namespace zeek::plugin::detail::Zeek_Geneve
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Geneve", zeek::analyzer::geneve::Geneve_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Geneve";
		config.description = "Geneve analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Geneve
