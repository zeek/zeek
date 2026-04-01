#include "Plugin.h"

#include <zeek/IntrusivePtr.h>

#include "XDPProgram.h"

namespace xdp::shunter {
Plugin plugin;
} // namespace xdp::shunter

using namespace xdp::shunter;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "XDP::Shunter";
    config.description = "Shunts traffic via an XDP program";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPostScript() { detail::program_opaque = zeek::make_intrusive<zeek::OpaqueType>("xdp::XDPProgram"); }
