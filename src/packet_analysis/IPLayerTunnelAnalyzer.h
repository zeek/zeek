// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>

#include "zeek/IPAddr.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/packet_analysis/TunnelAnalyzer.h"

namespace zeek::packet_analysis {

namespace detail {
class IPLayerTunnelTimer;
}

class IPLayerTunnelAnalyzer : public TunnelAnalyzer {
public:
    using TunnelAnalyzer::TunnelAnalyzer;

protected:
    struct InnerPacketResult {
        std::unique_ptr<Packet> packet;
    };

    // Registers tunnel activity for the outer IP pair and builds a
    // synthetic inner packet. Manages the IP-pair map, assigns stable UIDs,
    // creates inactivity timers, and attaches the EncapsulatingConn to the
    // inner packet's encap stack.
    // Returns a null packet if packet->ip_hdr is null.
    InnerPacketResult BuildInnerPacket(Packet* outer, size_t len, const uint8_t* data,
                                       BifEnum::Tunnel::Type tunnel_type);

private:
    friend class detail::IPLayerTunnelTimer;

    using IPPair = std::pair<IPAddr, IPAddr>;
    using TunnelActivity = std::pair<EncapsulatingConn, double>;
    using IPTunnelMap = std::map<IPPair, TunnelActivity>;
    IPTunnelMap ip_tunnels;
};

namespace detail {

class IPLayerTunnelTimer final : public zeek::detail::Timer {
public:
    IPLayerTunnelTimer(double t, IPLayerTunnelAnalyzer::IPPair p, IPLayerTunnelAnalyzer* analyzer);
    void Dispatch(double t, bool is_expire) override;

private:
    IPLayerTunnelAnalyzer::IPPair tunnel_idx;
    IPLayerTunnelAnalyzer* analyzer;
};

} // namespace detail

} // namespace zeek::packet_analysis
