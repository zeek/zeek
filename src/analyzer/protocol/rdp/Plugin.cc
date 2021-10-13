#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/rdp/RDP.h"
#include "zeek/analyzer/protocol/rdp/RDPEUDP.h"

namespace zeek::plugin::detail::Zeek_RDP
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"RDP", zeek::analyzer::rdp::RDP_Analyzer::InstantiateAnalyzer));
		AddComponent(new zeek::analyzer::Component(
			"RDPEUDP", zeek::analyzer::rdpeudp::RDP_Analyzer::InstantiateAnalyzer));

		zeek::plugin::Configuration config;
		config.name = "Zeek::RDP";
		config.description = "RDP analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_RDP
