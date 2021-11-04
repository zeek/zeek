// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/pia/PIA.h"

namespace zeek::plugin::detail::Zeek_PIA
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("PIA_TCP", zeek::analyzer::pia::PIA_TCP::Instantiate));
		AddComponent(
			new zeek::analyzer::Component("PIA_UDP", zeek::analyzer::pia::PIA_UDP::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::PIA";
		config.description = "Analyzers implementing Dynamic Protocol";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_PIA
