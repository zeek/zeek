// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "ARP.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_ARP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("ARP",
		                 zeek::llanalyzer::ARP::ARPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::ARP";
		config.description = "ARP LL-Analyzer";
		return config;
		}

} plugin;

}
