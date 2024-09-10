// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/packet_analysis/Component.h"

#include "packet_analysis/protocol/unknown_ip_transport/UnknownIPTransport.h"

namespace zeek::plugin::Zeek_Unknown_IP_Transport {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::packet_analysis::
                         Component("Unknown_IP_Transport",
                                   zeek::packet_analysis::UnknownIPTransport::UnknownIPTransportAnalyzer::Instantiate));
        AddComponent(new zeek::analyzer::Component("Unknown_IP_Transport", nullptr, 0, true, false, true));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Unknown_IP_Transport";
        config.description = "Packet analyzer for unknown IP protocols";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_Unknown_IP_Transport
