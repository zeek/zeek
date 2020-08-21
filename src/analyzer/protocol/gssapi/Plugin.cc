// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "GSSAPI.h"

namespace zeek::plugin::detail::Zeek_GSSAPI {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("GSSAPI", zeek::analyzer::gssapi::GSSAPI_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::GSSAPI";
		config.description = "GSSAPI analyzer";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_GSSAPI
