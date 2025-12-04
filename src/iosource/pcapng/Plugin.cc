// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/iosource/Component.h"
#include "zeek/iosource/pcapng/Source.h"

namespace zeek::plugin::detail::Zeek_Pcapng {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new iosource::PktSrcComponent("PcapngReader", "pcapng", iosource::PktSrcComponent::BOTH,
                                                   iosource::pcapng::Source::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Pcap";
        config.description = "Packet acquisition via pcapng";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_Pcapng
