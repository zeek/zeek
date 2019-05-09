// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv4.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_IPv4 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IPv4",
		                 zeek::llanalyzer::IPv4::IPv4Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::IPv4";
		config.description = "IPv4 LL-Analyzer";
		return config;
		}

} plugin;

}
