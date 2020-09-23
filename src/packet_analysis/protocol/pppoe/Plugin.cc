// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPoE.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_PPPoE {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure()
        {
        AddComponent(new zeek::packet_analysis::Component("PPPoE",
                         zeek::packet_analysis::PPPoE::PPPoEAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::PPPoE";
        config.description = "PPPoE packet analyzer";
        return config;
        }

} plugin;

}
