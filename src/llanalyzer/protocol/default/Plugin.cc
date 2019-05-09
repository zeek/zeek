// See the file "COPYING" in the main distribution directory for copyright.

#include "Default.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_Default {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("DefaultAnalyzer",
		                 zeek::llanalyzer::Default::DefaultAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::DefaultAnalyzer";
		config.description = "Default LL-Analyzer for IP fallback";
		return config;
		}

} plugin;

}
