// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/IPLayerTunnelAnalyzer.h"

#include <pcap.h>
#include <cassert>

#include "zeek/RunState.h"
#include "zeek/Timer.h"

namespace zeek::packet_analysis {

IPLayerTunnelAnalyzer::InnerPacketResult IPLayerTunnelAnalyzer::BuildInnerPacket(Packet* outer, size_t len,
                                                                                 const uint8_t* data,
                                                                                 BifEnum::Tunnel::Type tunnel_type) {
    InnerPacketResult result;

    if ( ! outer->ip_hdr )
        return result;

    // Register/update the tunnel in the IP-pair map.
    IPPair tunnel_idx;
    if ( outer->ip_hdr->SrcAddr() < outer->ip_hdr->DstAddr() )
        tunnel_idx = IPPair(outer->ip_hdr->SrcAddr(), outer->ip_hdr->DstAddr());
    else
        tunnel_idx = IPPair(outer->ip_hdr->DstAddr(), outer->ip_hdr->SrcAddr());

    IPTunnelMap::iterator it = ip_tunnels.find(tunnel_idx);

    if ( it == ip_tunnels.end() ) {
        EncapsulatingConn ec(outer->ip_hdr->SrcAddr(), outer->ip_hdr->DstAddr(), tunnel_type,
                             outer->ip_hdr->NextProto());
        ip_tunnels[tunnel_idx] = TunnelActivity(ec, run_state::network_time);
        zeek::detail::timer_mgr->Add(new detail::IPLayerTunnelTimer(run_state::network_time, tunnel_idx, this));
    }
    else
        it->second.second = zeek::run_state::network_time;

    // Build the synthetic inner packet.
    assert(outer->cap_len >= len);
    assert(outer->len >= outer->cap_len - len);

    uint32_t consumed_len = outer->cap_len - static_cast<uint32_t>(len);
    uint32_t inner_wire_len = outer->len - consumed_len;

    result.packet = std::make_unique<Packet>(DLT_RAW, &outer->ts, static_cast<uint32_t>(len), inner_wire_len, data);

    // Attach the encapsulation stack to the inner packet.
    auto encap = outer->encap ? outer->encap : std::make_shared<EncapsulationStack>();
    encap->Add(ip_tunnels[tunnel_idx].first);
    result.packet->encap = std::move(encap);

    return result;
}

namespace detail {

IPLayerTunnelTimer::IPLayerTunnelTimer(double t, IPLayerTunnelAnalyzer::IPPair p, IPLayerTunnelAnalyzer* analyzer)
    : Timer(t + BifConst::Tunnel::ip_tunnel_timeout, zeek::detail::TIMER_IP_TUNNEL_INACTIVITY),
      tunnel_idx(std::move(p)),
      analyzer(analyzer) {}

void IPLayerTunnelTimer::Dispatch(double t, bool is_expire) {
    auto it = analyzer->ip_tunnels.find(tunnel_idx);

    if ( it == analyzer->ip_tunnels.end() )
        return;

    double last_active = it->second.second;
    double inactive_time = t > last_active ? t - last_active : 0;

    if ( inactive_time >= BifConst::Tunnel::ip_tunnel_timeout )
        analyzer->ip_tunnels.erase(tunnel_idx);
    else if ( ! is_expire )
        zeek::detail::timer_mgr->Add(new IPLayerTunnelTimer(t, tunnel_idx, analyzer));
}

} // namespace detail

} // namespace zeek::packet_analysis
