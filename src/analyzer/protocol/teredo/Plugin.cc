// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/teredo/Teredo.h"

namespace zeek::plugin::detail::Zeek_Teredo
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Teredo", zeek::analyzer::teredo::Teredo_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Teredo";
		config.description = "Teredo analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Teredo
