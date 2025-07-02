// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UnknownIPTransport {

class UnknownIPSessionAdapter;

class UnknownIPTransportAnalyzer final : public IP::IPBasedAnalyzer {
public:
    UnknownIPTransportAnalyzer();
    ~UnknownIPTransportAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<UnknownIPTransportAnalyzer>(); }

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;

protected:
    bool InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) override;

    void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;
};

} // namespace zeek::packet_analysis::UnknownIPTransport
