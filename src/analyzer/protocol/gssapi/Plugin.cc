// See the file in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/protocol/gssapi/GSSAPI.h"

namespace zeek::plugin::detail::Zeek_GSSAPI
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"GSSAPI", zeek::analyzer::gssapi::GSSAPI_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::GSSAPI";
		config.description = "GSSAPI analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_GSSAPI
