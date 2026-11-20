// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::L2TP {

/**
 * Analyzer for the L2TP protocol. It only supports L2TPv2 at the moment, with
 * intentions to support V3 later. See https://www.rfc-editor.org/rfc/rfc2661.html for
 * more information about the protocol.
 */
class L2TPAnalyzer : public zeek::packet_analysis::Analyzer {
public:
    L2TPAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<L2TPAnalyzer>(); }
};

} // namespace zeek::packet_analysis::L2TP
