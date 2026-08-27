// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/IPLayerTunnelAnalyzer.h"

namespace zeek::packet_analysis::IPInIP {

class IPInIPAnalyzer : public IPLayerTunnelAnalyzer {
public:
    IPInIPAnalyzer();
    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;
    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<IPInIPAnalyzer>(); }
};

} // namespace zeek::packet_analysis::IPInIP
