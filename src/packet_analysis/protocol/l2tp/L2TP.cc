// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/l2tp/L2TP.h"

using namespace zeek::packet_analysis::L2TP;

L2TPAnalyzer::L2TPAnalyzer() : zeek::packet_analysis::Analyzer("L2TP") {}

bool L2TPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    // There are 3 words in the header that are required. Bail if these are missing.
    if ( len < 6 ) {
        Weird("l2tp_header_truncated");
        return false;
    }

    bool data_message = (data[0] & 0x80) == 0;
    bool has_length = (data[0] & 0x40) == 0x40;
    bool has_ns_nr = (data[0] & 0x08) == 0x08;
    bool has_offset = (data[0] & 0x02) == 0x02;

    // TODO: v3 support is more difficult, but should be doable.
    uint8_t version = data[1] & 0x0F;
    if ( version != 2 ) {
        Weird("l2tp_unsupported_version", packet, util::fmt("%d", version));
        return false;
    }

    // flags + tunnel_id + session_id.
    uint16_t header_size = 6;

    if ( has_length )
        // optional message length field
        header_size += 2;

    if ( has_ns_nr )
        // optional ns and nr fields
        header_size += 4;

    if ( len < header_size ) {
        Weird("l2tp_header_truncated");
        return false;
    }

    // The optional length field is the total message length in bytes including the size
    // of the header. This will be adjusted as the rest of the optional fields are parsed.
    uint16_t msg_len = 0;
    if ( has_length ) {
        // optional msg_len field
        msg_len = data[2];
        msg_len <<= 8;
        msg_len |= data[3];
        msg_len -= header_size;
    }

    data += header_size;
    len -= header_size;

    // If the flag for the optional offset length is set, read that field and skip that
    // many bytes
    if ( has_offset ) {
        // We skipped up to where the offset started, but we need at least two bytes to
        // read the offset itself.
        if ( len < 2 ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        uint16_t offset_len = data[0];
        offset_len <<= 8;
        offset_len |= data[1];
        offset_len += 2;

        if ( len < offset_len ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        data += offset_len;
        len -= offset_len;
        msg_len -= offset_len;
    }

    // If this is a control message, the payload doesn't matter and can be skipped.
    // There's also nothing to forward.
    if ( ! data_message ) {
        if ( len < msg_len ) {
            Weird("l2tp_control_message_truncated");
            return false;
        }

        // TODO: add an event here that contains the key/value pairs from control messages
        return true;
    }

    return ForwardPacket(len, data, packet);
}
