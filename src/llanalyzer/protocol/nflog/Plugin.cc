// See the file "COPYING" in the main distribution directory for copyright.

#include "NFLog.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_NFLog {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("NFLog",
		                 zeek::llanalyzer::NFLog::NFLogAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::NFLog";
		config.description = "NFLog LL-Analyzer";
		return config;
		}
} plugin;

}
