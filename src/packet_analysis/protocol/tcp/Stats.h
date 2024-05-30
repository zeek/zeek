// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <array>
#include <memory>

#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"

namespace zeek::telemetry {
class Gauge;
}

namespace zeek::packet_analysis::TCP {

/**
 * A TCPStateStats object tracks the distribution of TCP states for
 * the currently active connections.
 */
class TCPStateStats {
public:
    TCPStateStats();
    ~TCPStateStats() = default;

    void ChangeState(analyzer::tcp::EndpointState o_prev, analyzer::tcp::EndpointState o_now,
                     analyzer::tcp::EndpointState r_prev, analyzer::tcp::EndpointState r_now);
    void FlipState(analyzer::tcp::EndpointState orig, analyzer::tcp::EndpointState resp);

    void StateEntered(analyzer::tcp::EndpointState o_state, analyzer::tcp::EndpointState r_state);
    void StateLeft(analyzer::tcp::EndpointState o_state, analyzer::tcp::EndpointState r_state);

    unsigned int Cnt(analyzer::tcp::EndpointState state) const;
    unsigned int Cnt(analyzer::tcp::EndpointState state1, analyzer::tcp::EndpointState state2) const;

    unsigned int NumStateEstablished() const { return Cnt(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED); }
    unsigned int NumStateHalfClose() const { // corresponds to S2,S3
        return Cnt(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED, analyzer::tcp::TCP_ENDPOINT_CLOSED) +
               Cnt(analyzer::tcp::TCP_ENDPOINT_CLOSED, analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
    }
    unsigned int NumStateHalfRst() const {
        return Cnt(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED, analyzer::tcp::TCP_ENDPOINT_RESET) +
               Cnt(analyzer::tcp::TCP_ENDPOINT_RESET, analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
    }
    unsigned int NumStateClosed() const { return Cnt(analyzer::tcp::TCP_ENDPOINT_CLOSED); }
    unsigned int NumStateRequest() const {
        assert(Cnt(analyzer::tcp::TCP_ENDPOINT_INACTIVE, analyzer::tcp::TCP_ENDPOINT_SYN_SENT) == 0);
        return Cnt(analyzer::tcp::TCP_ENDPOINT_SYN_SENT, analyzer::tcp::TCP_ENDPOINT_INACTIVE);
    }
    unsigned int NumStateSuccRequest() const {
        return Cnt(analyzer::tcp::TCP_ENDPOINT_SYN_SENT, analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT) +
               Cnt(analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT, analyzer::tcp::TCP_ENDPOINT_SYN_SENT);
    }
    unsigned int NumStateRstRequest() const {
        return Cnt(analyzer::tcp::TCP_ENDPOINT_SYN_SENT, analyzer::tcp::TCP_ENDPOINT_RESET) +
               Cnt(analyzer::tcp::TCP_ENDPOINT_RESET, analyzer::tcp::TCP_ENDPOINT_SYN_SENT);
    }
    unsigned int NumStateInactive() const { return Cnt(analyzer::tcp::TCP_ENDPOINT_INACTIVE); }
    unsigned int NumStatePartial() const;

    void PrintStats(File* file, const char* prefix);

private:
    std::shared_ptr<telemetry::Gauge> state_cnt[analyzer::tcp::TCP_ENDPOINT_RESET + 1]
                                               [analyzer::tcp::TCP_ENDPOINT_RESET + 1];
};

} // namespace zeek::packet_analysis::TCP
