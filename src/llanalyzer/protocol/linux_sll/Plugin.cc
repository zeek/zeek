// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "LinuxSLL.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_LinuxSLL {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("LinuxSLL",
		                 zeek::llanalyzer::LinuxSLL::LinuxSLLAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::LinuxSLL";
		config.description = "Linux cooked capture (SLL) LL-Analyzer";
		return config;
		}

} plugin;

}
