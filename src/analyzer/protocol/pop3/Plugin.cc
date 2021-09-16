// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/pop3/POP3.h"

namespace zeek::plugin::detail::Zeek_POP3
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"POP3", zeek::analyzer::pop3::POP3_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::POP3";
		config.description = "POP3 analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_POP3
