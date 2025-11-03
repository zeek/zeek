// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::Novell_802_3 {

class Novell_802_3Analyzer : public Analyzer {
public:
    Novell_802_3Analyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<Novell_802_3Analyzer>(); }
};

} // namespace zeek::packet_analysis::Novell_802_3
