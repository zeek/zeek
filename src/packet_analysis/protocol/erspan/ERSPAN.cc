// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/erspan/ERSPAN.h"

namespace zeek::packet_analysis::ERSPAN {

ERSPANAnalyzer::ERSPANAnalyzer() : zeek::packet_analysis::Analyzer("ERSPAN") {}

bool ERSPANAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( len < 8 ) {
        Weird("truncated_ERSPAN", packet);
        return false;
    }

    unsigned int erspan_len = 0;

    // The version field in bits 0-3 of the first byte distinguishes types.
    uint8_t version = data[0] >> 4;

    if ( version == 1 ) {
        // ERSPAN Type II: 8-byte header
        erspan_len = 8;
    }
    else if ( version == 2 ) {
        // ERSPAN Type III: 12-byte header + optional 8-byte sub-header
        if ( len < 12 ) {
            Weird("truncated_ERSPAN", packet);
            return false;
        }

        erspan_len = 12;

        // Check the O-bit (optional sub-header present) in the last byte of the header.
        bool have_opt_header = (data[11] & 0x01) == 0x01;
        if ( have_opt_header ) {
            erspan_len += 8;
            if ( len < erspan_len ) {
                Weird("truncated_ERSPAN", packet);
                return false;
            }
        }
    }
    else {
        Weird("unknown_ERSPAN_version", packet);
        return false;
    }

    data += erspan_len;
    len -= erspan_len;

    // The remaining data is an Ethernet frame.
    return ForwardPacket(len, data, packet);
}

} // namespace zeek::packet_analysis::ERSPAN
