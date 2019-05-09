// See the file "COPYING" in the main distribution directory for copyright.

#include "MPLS.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_MPLS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("MPLS",
		                 zeek::llanalyzer::MPLS::MPLSAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::MPLS";
		config.description = "MPLS LL-Analyzer";
		return config;
		}

} plugin;

}
