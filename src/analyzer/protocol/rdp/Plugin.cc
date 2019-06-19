#include "plugin/Plugin.h"

#include "RDP.h"

namespace plugin {
namespace Bro_RDP {

class Plugin : public plugin::Plugin {
public:
        plugin::Configuration Configure()
                {
                AddComponent(new ::analyzer::Component("RDP", ::analyzer::rdp::RDP_Analyzer::InstantiateAnalyzer));

                plugin::Configuration config;
                config.name = "Bro::RDP";
                config.description = "RDP analyzer";
                return config;
                }
} plugin;

}
}
