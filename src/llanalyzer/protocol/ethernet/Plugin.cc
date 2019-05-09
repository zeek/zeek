// See the file "COPYING" in the main distribution directory for copyright.

#include "Ethernet.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_Ethernet {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("Ethernet",
		                 zeek::llanalyzer::Ethernet::EthernetAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::Ethernet";
		config.description = "Ethernet LL-Analyzer";
		return config;
		}

} plugin;

}
