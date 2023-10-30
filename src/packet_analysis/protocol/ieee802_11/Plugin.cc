// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ieee802_11/IEEE802_11.h"

namespace zeek::plugin::Zeek_IEEE802_11 {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("IEEE802_11",
                                                 zeek::packet_analysis::IEEE802_11::IEEE802_11Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::IEEE802_11";
        config.description = "IEEE 802.11 packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_IEEE802_11
