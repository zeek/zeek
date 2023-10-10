// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ppp/PPP.h"

using namespace zeek::packet_analysis::PPP;

PPPAnalyzer::PPPAnalyzer() : zeek::packet_analysis::Analyzer("PPP") {}

bool PPPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    // Analyzer is meant to handle DLT_PPP.
    //
    // From https://www.tcpdump.org/linktypes.html for LINKTYPE_PPP (0x9):
    //
    //   PPP, as per RFC 1661 and RFC 1662; if the first 2 bytes are 0xff and 0x03,
    //   it's PPP in HDLC-like framing, with the PPP header following those two bytes,
    //   otherwise it's PPP without framing, and the packet begins with the PPP header.
    //   The data in the frame is not octet-stuffed or bit-stuffed.
    if ( 2 >= len ) {
        Weird("truncated_ppp_header", packet);
        return false;
    }

    if ( data[0] == 0xff && data[1] == 0x03 ) {
        // HDLC-Framing
        if ( 4 >= len ) {
            Weird("truncated_ppp_hdlc_header", packet);
            return false;
        }

        uint32_t protocol = (data[2] << 8) + data[3];
        return ForwardPacket(len - 4, data + 4, packet, protocol);
    }

    uint32_t protocol = (data[0] << 8) + data[1];
    return ForwardPacket(len - 2, data + 2, packet, protocol);
}
