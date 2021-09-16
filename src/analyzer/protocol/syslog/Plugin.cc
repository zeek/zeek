// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/syslog/Syslog.h"

namespace zeek::plugin::detail::Zeek_Syslog
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"Syslog", zeek::analyzer::syslog::Syslog_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Syslog";
		config.description = "Syslog analyzer UDP-only";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Syslog
