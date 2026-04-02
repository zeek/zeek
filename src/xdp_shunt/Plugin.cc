// See the file "COPYING" in the main distribution directory for copyright.

#include "Plugin.h"

#include "zeek/IntrusivePtr.h"

#include "XDPProgram.h"

namespace zeek::plugin::detail::Zeek_XDP_Shunter {
Plugin plugin;
} // namespace zeek::plugin::detail::Zeek_XDP_Shunter

using namespace zeek::plugin::detail::Zeek_XDP_Shunter;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::XDP_Shunter";
    config.description = "Shunts traffic via an XDP program";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPostScript() { program_opaque = zeek::make_intrusive<zeek::OpaqueType>("XDP::Program"); }
