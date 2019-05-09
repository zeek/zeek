// See the file "COPYING" in the main distribution directory for copyright.

#include "Wrapper.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("Wrapper",
		                 zeek::llanalyzer::Wrapper::WrapperAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::Wrapper";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
