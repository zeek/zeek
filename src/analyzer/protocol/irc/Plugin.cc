// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/irc/IRC.h"

namespace zeek::plugin::detail::Zeek_IRC
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("IRC", zeek::analyzer::irc::IRC_Analyzer::Instantiate));
		AddComponent(
			new zeek::analyzer::Component("IRC_Data", zeek::analyzer::file::IRC_Data::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IRC";
		config.description = "IRC analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_IRC
