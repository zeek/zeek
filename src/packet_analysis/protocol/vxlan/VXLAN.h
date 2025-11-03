// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::VXLAN {

class VXLAN_Analyzer : public zeek::packet_analysis::Analyzer {
public:
    VXLAN_Analyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<VXLAN_Analyzer>(); }
};

} // namespace zeek::packet_analysis::VXLAN
