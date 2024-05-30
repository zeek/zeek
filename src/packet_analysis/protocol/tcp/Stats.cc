// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/Stats.h"

#include "zeek/File.h"
#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/telemetry/Manager.h"

namespace zeek::packet_analysis::TCP {

static const char* state_to_string(analyzer::tcp::EndpointState state) {
    switch ( state ) {
        case analyzer::tcp::TCP_ENDPOINT_INACTIVE: return "inactive";
        case analyzer::tcp::TCP_ENDPOINT_SYN_SENT: return "syn_sent";
        case analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT: return "syn_ack_sent";
        case analyzer::tcp::TCP_ENDPOINT_PARTIAL: return "partial";
        case analyzer::tcp::TCP_ENDPOINT_ESTABLISHED: return "established";
        case analyzer::tcp::TCP_ENDPOINT_CLOSED: return "closed";
        case analyzer::tcp::TCP_ENDPOINT_RESET: return "reset";
    }
}

TCPStateStats::TCPStateStats() {
    std::shared_ptr<telemetry::GaugeFamily> family =
        telemetry_mgr->GaugeFamily("zeek", "tcp_stats", {"orig", "resp"}, "");

    for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i )
        for ( int j = 0; j < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++j )
            state_cnt[i][j] =
                family->GetOrAdd({{"orig", state_to_string(static_cast<analyzer::tcp::EndpointState>(i))},
                                  {"resp", state_to_string(static_cast<analyzer::tcp::EndpointState>(j))}});
}

void TCPStateStats::ChangeState(analyzer::tcp::EndpointState o_prev, analyzer::tcp::EndpointState o_now,
                                analyzer::tcp::EndpointState r_prev, analyzer::tcp::EndpointState r_now) {
    state_cnt[o_prev][r_prev]->Dec();
    state_cnt[o_now][r_now]->Inc();
}

void TCPStateStats::FlipState(analyzer::tcp::EndpointState orig, analyzer::tcp::EndpointState resp) {
    state_cnt[orig][resp]->Dec();
    state_cnt[resp][orig]->Inc();
}

void TCPStateStats::StateEntered(analyzer::tcp::EndpointState o_state, analyzer::tcp::EndpointState r_state) {
    state_cnt[o_state][r_state]->Inc();
}
void TCPStateStats::StateLeft(analyzer::tcp::EndpointState o_state, analyzer::tcp::EndpointState r_state) {
    state_cnt[o_state][r_state]->Dec();
}

unsigned int TCPStateStats::Cnt(analyzer::tcp::EndpointState state) const { return Cnt(state, state); }
unsigned int TCPStateStats::Cnt(analyzer::tcp::EndpointState state1, analyzer::tcp::EndpointState state2) const {
    return static_cast<unsigned int>(state_cnt[state1][state2]->Value());
}

unsigned int TCPStateStats::NumStatePartial() const {
    double sum = 0;
    for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i ) {
        sum += state_cnt[analyzer::tcp::TCP_ENDPOINT_PARTIAL][i]->Value();
        sum += state_cnt[i][analyzer::tcp::TCP_ENDPOINT_PARTIAL]->Value();
    }

    return static_cast<unsigned int>(sum);
}

void TCPStateStats::PrintStats(File* file, const char* prefix) {
    file->Write(prefix);
    file->Write("        Inact.  Syn.    SA      Part.   Est.    Fin.    Rst.\n");

    for ( int i = 0; i < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++i ) {
        file->Write(prefix);

        switch ( i ) {
#define STATE_STRING(state, str)                                                                                       \
    case state: file->Write(str); break;
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_INACTIVE, "Inact.");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_SYN_SENT, "Syn.  ");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT, "SA    ");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_PARTIAL, "Part. ");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED, "Est.  ");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_CLOSED, "Fin.  ");
            STATE_STRING(analyzer::tcp::TCP_ENDPOINT_RESET, "Rst.  ");
        }

        file->Write("  ");

        for ( int j = 0; j < analyzer::tcp::TCP_ENDPOINT_RESET + 1; ++j ) {
            unsigned int n = static_cast<unsigned int>(state_cnt[i][j]->Value());
            if ( n > 0 ) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%-8d", n);
                file->Write(buf);
            }
            else
                file->Write("        ");
        }

        file->Write("\n");
    }
}

} // namespace zeek::packet_analysis::TCP
