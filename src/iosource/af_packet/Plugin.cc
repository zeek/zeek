// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/iosource/Component.h"
#include "zeek/iosource/af_packet/AF_Packet.h"

namespace zeek::plugin::Zeek_AF_Packet {

class Plugin : public plugin::Plugin {
    plugin::Configuration Configure() override {
        AddComponent(
            new ::zeek::iosource::PktSrcComponent("AF_PacketReader", "af_packet",
                                                  ::zeek::iosource::PktSrcComponent::LIVE,
                                                  ::zeek::iosource::pktsrc::AF_PacketSource::InstantiateAF_Packet));

        zeek::plugin::Configuration config;
        config.name = "Zeek::AF_Packet";
        config.description = "Packet acquisition via AF_Packet";
        config.version.major = 4;
        config.version.minor = 0;
        config.version.patch = 0;
        return config;
    }
} plugin;

} // namespace zeek::plugin::Zeek_AF_Packet
