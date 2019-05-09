// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "IPv6.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_IPv6 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IPv6",
		             zeek::llanalyzer::IPv6::IPv6Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::IPv6";
		config.description = "IPv6 LL-Analyzer";
		return config;
		}
} plugin;

}
