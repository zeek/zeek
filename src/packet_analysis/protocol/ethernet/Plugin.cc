// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ethernet/Ethernet.h"

namespace zeek::plugin::Zeek_Ethernet {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("Ethernet",
                                                 zeek::packet_analysis::Ethernet::EthernetAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Ethernet";
        config.description = "Ethernet packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_Ethernet
