// See the file "COPYING" in the main distribution directory for copyright.

#include "Plugin.h"

#include "zeek/iosource/Component.h"

#include "AF_Packet.h"

namespace plugin::Zeek_AF_Packet {
Plugin plugin;
}

using namespace af_packet::plugin::Zeek_AF_Packet;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(
        new ::zeek::iosource::PktSrcComponent("AF_PacketReader", "af_packet", ::zeek::iosource::PktSrcComponent::LIVE,
                                              ::zeek::iosource::pktsrc::AF_PacketSource::InstantiateAF_Packet));

    zeek::plugin::Configuration config;
    config.name = "Zeek::AF_Packet";
    config.description = "Packet acquisition via AF_Packet";
    config.version.major = 4;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}
