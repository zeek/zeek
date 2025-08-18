// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zeek/plugin/Plugin.h>

namespace af_packet::plugin::Zeek_AF_Packet {

class Plugin : public zeek::plugin::Plugin {
protected:
    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace plugin::Zeek_AF_Packet
