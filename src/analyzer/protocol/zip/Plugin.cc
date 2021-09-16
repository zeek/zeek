// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/zip/ZIP.h"

namespace zeek::plugin::detail::Zeek_ZIP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("ZIP", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ZIP";
		config.description = "Generic ZIP support analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_ZIP
