// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/http/HTTP.h"

namespace zeek::plugin::detail::Zeek_HTTP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"HTTP", zeek::analyzer::http::HTTP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::HTTP";
		config.description = "HTTP analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_HTTP
