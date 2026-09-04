// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/SessionTunnelAnalyzer.h"

#include <cassert>

#include "zeek/Conn.h"
#include "zeek/TunnelEncapsulation.h"

namespace zeek::packet_analysis {

bool SessionTunnelAnalyzer::ValidateSession(Packet* packet) {
    if ( ! packet->session ) {
        Weird("tunnel_missing_connection", packet);
        return false;
    }

    if ( AnalyzerViolated(packet->session) )
        return false;

    return true;
}

SessionTunnelAnalyzer::InnerPacketResult SessionTunnelAnalyzer::BuildInnerPacket(Packet* outer, size_t len,
                                                                                 const uint8_t* data, int link_type,
                                                                                 BifEnum::Tunnel::Type tunnel_type) {
    InnerPacketResult result;

    assert(outer->cap_len >= len);
    assert(outer->len >= outer->cap_len - len);

    uint32_t consumed_len = outer->cap_len - static_cast<uint32_t>(len);
    uint32_t inner_wire_len = outer->len - consumed_len;

    result.packet = std::make_unique<Packet>(link_type, &outer->ts, static_cast<uint32_t>(len), inner_wire_len, data);
    result.packet->l2_src = Packet::L2_EMPTY_ADDR;
    result.packet->l2_dst = Packet::L2_EMPTY_ADDR;

    result.encap_index = 0;
    if ( outer->session ) {
        EncapsulatingConn ec(static_cast<Connection*>(outer->session), tunnel_type);

        if ( ! outer->encap )
            outer->encap = std::make_shared<EncapsulationStack>();

        outer->encap->Add(ec);
        result.packet->encap = outer->encap;
        result.encap_index = outer->encap->Depth();
    }

    return result;
}

} // namespace zeek::packet_analysis
