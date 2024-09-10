// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/packet_analysis/Component.h"

#include "packet_analysis/protocol/unknown_ip/UnknownIP.h"

namespace zeek::plugin::Zeek_Unknown_IP {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("Unknown_IP",
                                                 zeek::packet_analysis::UnknownIP::UnknownIPAnalyzer::Instantiate));
        AddComponent(new zeek::analyzer::Component("Unknown_IP", nullptr, 0, true, false, true));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Unknown_IP";
        config.description = "Packet analyzer for unknown IP protocols";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_Unknown_IP
