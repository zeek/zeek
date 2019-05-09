// See the file "COPYING" in the main distribution directory for copyright.

#include "FDDI.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_FDDI {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("FDDI",
		                 zeek::llanalyzer::FDDI::FDDIAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::FDDI";
		config.description = "FDDI LL-Analyzer";
		return config;
		}

} plugin;

}
