// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/gre/GRE.h"

#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::GRE;

static unsigned int gre_header_len(uint16_t flags = 0) {
    unsigned int len = 4; // Always has 2 byte flags and 2 byte protocol type.

    if ( flags & 0x8000 )
        // Checksum/Reserved1 present.
        len += 4;

    // Not considering routing presence bit since it's deprecated ...

    if ( flags & 0x2000 )
        // Key present.
        len += 4;

    if ( flags & 0x1000 )
        // Sequence present.
        len += 4;

    if ( flags & 0x0080 )
        // Acknowledgement present.
        len += 4;

    return len;
}

GREAnalyzer::GREAnalyzer() : zeek::packet_analysis::IPLayerTunnelAnalyzer("GRE") {}

bool GREAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! packet->ip_hdr ) {
        reporter->InternalError("GREAnalyzer: ip_hdr not provided from earlier analyzer");
        return false;
    }

    if ( ! CheckTunnelDepth(packet) )
        return false;

    if ( len < gre_header_len() ) {
        Weird("truncated_GRE", packet);
        return false;
    }

    uint16_t flags_ver = ntohs(*reinterpret_cast<const uint16_t*>(data + 0));
    uint16_t proto_typ = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    int gre_version = flags_ver & 0x0007;

    unsigned int gre_len = gre_header_len(flags_ver);
    unsigned int pptp_len = gre_version == 1 ? 4 : 0;

    if ( gre_version != 0 && gre_version != 1 ) {
        Weird("unknown_gre_version", packet, util::fmt("version=%d", gre_version));
        return false;
    }

    uint16_t proto = proto_typ;

    if ( gre_version == 1 ) {
        if ( proto_typ != 0x880b ) {
            // Enhanced GRE payload must be PPTP.
            Weird("egre_protocol_type", packet, util::fmt("proto=%d", proto_typ));
            return false;
        }
    }
    else {
        // GRE version 0: determine the inner protocol for dispatch.
        if ( proto_typ == 0x88be ) {
            // ERSPAN Type I or II. Distinguish by the sequence bit:
            // sequence present → Type II (has ERSPAN header), dispatch to ERSPAN.
            // no sequence → Type I (no ERSPAN header, just Ethernet), dispatch to Ethernet.
            if ( ! (flags_ver & 0x1000) ) {
                // Type I: no ERSPAN header, inner is raw Ethernet.
                proto = 0x6558;
            }
            // else: Type II stays as 0x88be, dispatches to ERSPAN analyzer.
        }
    }

    if ( flags_ver & 0x4000 ) {
        // RFC 2784 deprecates the variable length routing field specified by RFC 1701. It could be
        // parsed here, but easiest to just skip for now.
        Weird("gre_routing", packet);
        return false;
    }

    if ( flags_ver & 0x0078 ) {
        // Expect last 4 bits of flags are reserved, undefined.
        Weird("unknown_gre_flags", packet);
        return false;
    }

    if ( len < gre_len + pptp_len ) {
        Weird("truncated_GRE", packet);
        return false;
    }

    // For GRE version 1/PPTP, determine the inner protocol from the PPTP header.
    if ( gre_version == 1 ) {
        uint16_t pptp_proto = ntohs(*reinterpret_cast<const uint16_t*>(data + gre_len + 2));

        if ( pptp_proto != 0x0021 && pptp_proto != 0x0057 ) {
            Weird("non_ip_packet_in_encap", packet);
            return false;
        }

        // Map PPP protocol IDs to ethertypes for dispatch.
        proto = (pptp_proto == 0x0021) ? 0x0800 : 0x86DD;
    }

    data += gre_len + pptp_len;
    len -= gre_len + pptp_len;

    // Build inner packet (registers tunnel, creates encap stack).
    auto inner = BuildInnerPacket(packet, len, data, BifEnum::Tunnel::GRE);
    if ( ! inner.packet )
        return false;

    // Forward to whatever protocol comes next via the dispatch table.
    return ForwardPacket(len, data, inner.packet.get(), proto);
}
