// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"

#include "zeek/packet_analysis/protocol/vxlan/events.bif.h"

using namespace zeek::packet_analysis::VXLAN;

VXLAN_Analyzer::VXLAN_Analyzer() : zeek::packet_analysis::SessionTunnelAnalyzer("VXLAN") {}

bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! ValidateSession(packet) )
        return false;

    if ( ! CheckTunnelDepth(packet) )
        return false;

    constexpr uint16_t hdr_size = 8;

    if ( hdr_size > len ) {
        AnalyzerViolation("VXLAN header truncation", packet->session, reinterpret_cast<const char*>(data), len);
        return false;
    }

    if ( (data[0] & 0x08) == 0 ) {
        AnalyzerViolation("VXLAN 'I' flag not set", packet->session, reinterpret_cast<const char*>(data), len);
        return false;
    }

    uint32_t vni = (static_cast<uint32_t>(data[4]) << 16u) | (static_cast<uint32_t>(data[5]) << 8u) | data[6];

    len -= hdr_size;
    data += hdr_size;

    // We've successfully parsed the VXLAN part, so we might as well confirm this.
    AnalyzerConfirmation(packet->session);

    if ( len == 0 ) {
        // A VXLAN header that isn't followed by a tunnelled packet seems weird.
        Weird("vxlan_empty_packet", packet);
        return false;
    }

    auto result = BuildInnerPacket(packet, len, data, DLT_RAW, BifEnum::Tunnel::VXLAN);

    bool analysis_succeeded = ForwardPacket(len, data, result.packet.get());

    if ( analysis_succeeded && vxlan_packet ) {
        EncapsulatingConn* ec = result.packet->encap->At(result.encap_index);
        if ( ec && ec->ip_hdr )
            packet->session->EnqueueEvent(vxlan_packet, nullptr, packet->session->GetVal(), ec->ip_hdr->ToPktHdrVal(),
                                          val_mgr->Count(vni));
    }

    return analysis_succeeded;
}
