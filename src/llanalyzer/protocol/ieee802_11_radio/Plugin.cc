// See the file "COPYING" in the main distribution directory for copyright.

#include "IEEE802_11_Radio.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_IEEE802_11_Radio {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IEEE802_11_Radio",
		                 zeek::llanalyzer::IEEE802_11_Radio::IEEE802_11_RadioAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::IEEE802_11_Radio";
		config.description = "IEEE 802.11 Radiotap LL-Analyzer";
		return config;
		}

} plugin;
}
