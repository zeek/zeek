// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis {

class TunnelAnalyzer : public Analyzer {
public:
    using Analyzer::Analyzer;

protected:
    // Returns false and emits "exceeded_tunnel_max_depth" weird if
    // the packet's encapsulation stack has reached the configured limit.
    bool CheckTunnelDepth(Packet* packet);
};

} // namespace zeek::packet_analysis
