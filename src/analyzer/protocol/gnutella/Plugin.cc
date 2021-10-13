// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/gnutella/Gnutella.h"

namespace zeek::plugin::detail::Zeek_Gnutella
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Gnutella", zeek::analyzer::gnutella::Gnutella_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Gnutella";
		config.description = "Gnutella analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Gnutella
