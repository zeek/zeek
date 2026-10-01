// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/IPLayerTunnelAnalyzer.h"

namespace zeek::packet_analysis::GRE {

class GREAnalyzer : public IPLayerTunnelAnalyzer {
public:
    GREAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<GREAnalyzer>(); }
};

} // namespace zeek::packet_analysis::GRE
