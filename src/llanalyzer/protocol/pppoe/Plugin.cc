// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPoE.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_PPPoE {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure()
        {
        AddComponent(new zeek::llanalyzer::Component("PPPoE",
                         zeek::llanalyzer::PPPoE::PPPoEAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "LLAnalyzer::PPPoE";
        config.description = "PPPoE LL-Analyzer";
        return config;
        }

} plugin;

}
