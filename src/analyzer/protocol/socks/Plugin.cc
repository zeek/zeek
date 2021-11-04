// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/socks/SOCKS.h"

namespace zeek::plugin::detail::Zeek_SOCKS
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"SOCKS", zeek::analyzer::socks::SOCKS_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SOCKS";
		config.description = "SOCKS analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SOCKS
