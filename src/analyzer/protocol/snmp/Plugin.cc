// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/snmp/SNMP.h"

namespace zeek::plugin::detail::Zeek_SNMP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"SNMP", zeek::analyzer::snmp::SNMP_Analyzer::InstantiateAnalyzer));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SNMP";
		config.description = "SNMP analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SNMP
