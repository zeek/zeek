// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "Null.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_Null {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("Null",
		                 zeek::llanalyzer::Null::NullAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::Null";
		config.description = "Null LL-Analyzer";
		return config;
		}

} plugin;

}
