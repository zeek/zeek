// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/iosource/Component.h"
#include "zeek/iosource/pcap/Dumper.h"
#include "zeek/iosource/pcap/Source.h"

namespace zeek::plugin::detail::Zeek_Pcap {

class Plugin : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        AddComponent(new iosource::PktSrcComponent("PcapReader", "pcap", iosource::PktSrcComponent::BOTH,
                                                   iosource::pcap::PcapSource::Instantiate,
                                                   {0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1}));
        AddComponent(new iosource::PktDumperComponent("PcapWriter", "pcap", iosource::pcap::PcapDumper::Instantiate));

        plugin::Configuration config;
        config.name = "Zeek::Pcap";
        config.description = "Packet acquisition via libpcap";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_Pcap
