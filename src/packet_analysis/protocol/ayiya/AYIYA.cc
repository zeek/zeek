// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ayiya/AYIYA.h"

using namespace zeek::packet_analysis::AYIYA;

AYIYAAnalyzer::AYIYAAnalyzer() : zeek::packet_analysis::SessionTunnelAnalyzer("AYIYA") {}

bool AYIYAAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! ValidateSession(packet) )
        return false;

    if ( ! CheckTunnelDepth(packet) )
        return false;

    // This will be expanded based on the header data, but it has to be at least
    // this long.
    size_t hdr_size = 8;

    if ( hdr_size > len ) {
        AnalyzerViolation("Truncated AYIYA", packet->session);
        return false;
    }

    size_t identity_len = 1 << (data[0] >> 4);
    uint8_t signature_len = (data[1] >> 4) * 4;
    hdr_size += identity_len + signature_len;

    // Double-check this one now that we know the actual full length of the header.
    if ( hdr_size > len ) {
        AnalyzerViolation("Truncated AYIYA", packet->session);
        return false;
    }

    uint8_t op_code = data[2] & 0x0F;

    // Check that op_code is the "forward" command. Everything else is ignored.
    // This isn't an error, it's just the end of our parsing.
    if ( op_code != 1 )
        return true;

    uint8_t next_header = data[3];

    len -= hdr_size;
    data += hdr_size;

    // We've successfully parsed the AYIYA part, so we might as well confirm this.
    AnalyzerConfirmation(packet->session);

    if ( len == 0 ) {
        // A AYIYA header that isn't followed by a tunnelled packet seems weird.
        Weird("ayiya_empty_packet", packet);
        return false;
    }

    auto result = BuildInnerPacket(packet, len, data, DLT_RAW, BifEnum::Tunnel::AYIYA);

    return ForwardPacket(len, data, result.packet.get(), next_header);
}

bool AYIYAAnalyzer::DetectProtocol(size_t len, const uint8_t* data, Packet* packet) {
    // These magic numbers are based on the old DPD entry, which was based on... something?
    return len >= 3 && data[1] == 0x52 && data[2] == 0x11;
}
