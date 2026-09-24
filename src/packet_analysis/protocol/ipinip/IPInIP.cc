// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ipinip/IPInIP.h"

#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"

namespace zeek::packet_analysis::IPInIP {

IPInIPAnalyzer::IPInIPAnalyzer() : IPLayerTunnelAnalyzer("IPINIP") {}

bool IPInIPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! packet->ip_hdr ) {
        reporter->InternalError("IPInIPAnalyzer: null ip_hdr in packet");
        return false;
    }

    if ( ! CheckTunnelDepth(packet) )
        return false;

    // Pre-validate the inner IP packet before committing to tunnel tracking.
    std::shared_ptr<IP_Hdr> inner = nullptr;
    auto result = packet_analysis::IP::ParsePacket(len, data, packet->proto, inner);

    if ( result == packet_analysis::IP::ParseResult::BAD_PROTOCOL )
        Weird("invalid_inner_IP_version", packet);
    else if ( result == packet_analysis::IP::ParseResult::CAPLEN_TOO_SMALL )
        Weird("truncated_inner_IP", packet);
    else if ( result == packet_analysis::IP::ParseResult::CAPLEN_TOO_LARGE )
        Weird("inner_IP_payload_length_mismatch", packet);

    if ( result != packet_analysis::IP::ParseResult::OK )
        return false;

    auto inner_pkt = BuildInnerPacket(packet, len, data, BifEnum::Tunnel::IP);
    if ( ! inner_pkt.packet )
        return false;

    return ForwardPacket(len, data, inner_pkt.packet.get());
}

} // namespace zeek::packet_analysis::IPInIP
