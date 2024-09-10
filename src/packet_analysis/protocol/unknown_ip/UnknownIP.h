// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UnknownIP {

class UnknownIPSessionAdapter;

class UnknownIPAnalyzer final : public IP::IPBasedAnalyzer {
public:
    UnknownIPAnalyzer();
    ~UnknownIPAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<UnknownIPAnalyzer>(); }

    packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;

protected:
    /**
     * Parse the header from the packet into a ConnTuple object.
     */
    bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple) override;

    void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;
};

} // namespace zeek::packet_analysis::UnknownIP
