
#include "Plugin.h"

namespace plugin {
namespace XDP_Shunter {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::XDP_Shunter;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "XDP::Shunter";
    config.description = "Shunts traffic via an XDP program";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}
