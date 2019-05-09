// See the file "COPYING" in the main distribution directory for copyright.

#include "IEEE802_11.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_IEEE802_11 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IEEE802_11",
		                 zeek::llanalyzer::IEEE802_11::IEEE802_11Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::IEEE802_11";
		config.description = "IEEE 802.11 LL-Analyzer";
		return config;
		}

} plugin;

}
