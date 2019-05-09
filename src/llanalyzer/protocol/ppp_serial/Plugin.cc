// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_PPPSerial {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("PPPSerial",
		                 zeek::llanalyzer::PPPSerial::PPPSerialAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::PPPSerial";
		config.description = "PPPSerial LL-Analyzer";
		return config;
		}

} plugin;

}
