#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/rfb/RFB.h"

namespace zeek::plugin::detail::Zeek_RFB
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component(
			"RFB", zeek::analyzer::rfb::RFB_Analyzer::InstantiateAnalyzer));

		zeek::plugin::Configuration config;
		config.name = "Zeek::RFB";
		config.description = "Parser for rfb (VNC) analyzer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_RFB
