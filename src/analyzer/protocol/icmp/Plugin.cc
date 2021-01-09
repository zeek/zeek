// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/icmp/ICMP.h"

namespace zeek::plugin::detail::Zeek_ICMP
{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"ICMP", zeek::analyzer::icmp::ICMP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ICMP";
		config.description = "ICMP analyzer";
		return config;
		}
	} plugin;

} // namespace zeek::plugin::detail::Zeek_ICMP
