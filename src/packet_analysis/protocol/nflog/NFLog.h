// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::NFLog {

class NFLogAnalyzer : public Analyzer {
public:
    NFLogAnalyzer();
    ~NFLogAnalyzer() override = default;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static AnalyzerPtr Instantiate() { return std::make_shared<NFLogAnalyzer>(); }
};

} // namespace zeek::packet_analysis::NFLog
