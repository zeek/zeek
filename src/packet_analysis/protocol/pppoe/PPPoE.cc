// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/pppoe/PPPoE.h"

using namespace zeek::packet_analysis::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer() : zeek::packet_analysis::Analyzer("PPPoE") {}

bool PPPoEAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( 8 >= len ) {
        Weird("truncated_pppoe_header", packet);
        return false;
    }

    size_t payload_length = (data[4] << 8u) + data[5];
    uint32_t protocol = (data[6] << 8u) + data[7];

    // PPPoE header is six bytes. The protocol identifier is not part of the header
    if ( payload_length != len - 6 ) {
        if ( payload_length < len - 6 )
            Weird("pppoe_extra_data_after_payload", packet);
        else
            Weird("pppoe_truncated_payload");
    }

    payload_length = payload_length >= 2 ? payload_length - 2 : 0;

    // Skip the PPPoE session and PPP header
    return ForwardPacket(std::min(payload_length, len - 8), data + 8, packet, protocol);
}
