// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/null/Null.h"

using namespace zeek::packet_analysis::Null;

NullAnalyzer::NullAnalyzer() : zeek::packet_analysis::Analyzer("Null") {}

bool NullAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( 4 >= len ) {
        Weird("null_analyzer_failed", packet);
        return false;
    }

    uint32_t protocol = (static_cast<uint32_t>(data[3]) << 24u) + (static_cast<uint32_t>(data[2]) << 16u) +
                        (static_cast<uint32_t>(data[1]) << 8u) + data[0];
    // skip link header
    return ForwardPacket(len - 4, data + 4, packet, protocol);
}
