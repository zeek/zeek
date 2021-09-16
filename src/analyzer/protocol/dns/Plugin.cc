// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/dns/DNS.h"

namespace zeek::plugin::detail::Zeek_DNS
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::analyzer::Component("DNS", zeek::analyzer::dns::DNS_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_DNS", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DNS";
		config.description = "DNS analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_DNS
