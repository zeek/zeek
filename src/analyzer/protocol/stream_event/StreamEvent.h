// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::stream_event {

class StreamEvent_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit StreamEvent_Analyzer(Connection* conn);

    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new StreamEvent_Analyzer(conn); }
};

} // namespace zeek::analyzer::stream_event
