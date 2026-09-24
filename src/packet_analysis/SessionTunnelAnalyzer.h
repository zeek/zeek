// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/packet_analysis/TunnelAnalyzer.h"

namespace zeek::packet_analysis {

class SessionTunnelAnalyzer : public TunnelAnalyzer {
public:
    using TunnelAnalyzer::TunnelAnalyzer;

protected:
    // Validates that packet->session is present and the analyzer has not
    // been violated. Returns false on failure.
    bool ValidateSession(Packet* packet);

    struct InnerPacketResult {
        std::unique_ptr<Packet> packet;
        int encap_index = 0;
    };

    // Builds the inner packet with encapsulation stack derived from the
    // connection.
    InnerPacketResult BuildInnerPacket(Packet* outer, size_t len, const uint8_t* data, int link_type,
                                       BifEnum::Tunnel::Type tunnel_type);
};

} // namespace zeek::packet_analysis
