// See the file "COPYING" in the main distribution directory for copyright.

#include "VLAN.h"
#include "plugin/Plugin.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_VLAN {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure()
        {
        AddComponent(new zeek::llanalyzer::Component("VLAN",
                         zeek::llanalyzer::VLAN::VLANAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "LLAnalyzer::VLAN";
        config.description = "VLAN LL-Analyzer";
        return config;
        }

} plugin;

}
