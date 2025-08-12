// See the file "COPYING" in the main distribution directory for copyright.

#include <binpac.h>

#include "zeek/Conn.h"
#include "zeek/ID.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/websocket/WebSocket.h"
#include "zeek/conn_key/Manager.h"
#include "zeek/fuzzers/FuzzBuffer.h"
#include "zeek/fuzzers/fuzzer-setup.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/session/Manager.h"

static constexpr auto FUZZ_ANALYZER_NAME = "websocket";

static zeek::Connection* add_connection() {
    static constexpr double network_time_start = 1439471031;
    zeek::run_state::detail::update_network_time(network_time_start);

    zeek::ConnKeyPtr ck = zeek::conn_key_mgr->GetFactory().NewConnKey();
    zeek::IPBasedConnKeyPtr key = zeek::IPBasedConnKeyPtr(static_cast<zeek::IPBasedConnKey*>(ck.release()));
    key->InitTuple(zeek::IPAddr("1.2.3.4"), htons(23132), zeek::IPAddr("5.6.7.8"), htons(80), TRANSPORT_TCP, false);

    zeek::Packet p;
    zeek::Connection* conn = new zeek::Connection(std::move(key), network_time_start, 1, &p);
    conn->SetTransport(TRANSPORT_TCP);
    zeek::session_mgr->Insert(conn);
    return conn;
}

static std::tuple<zeek::analyzer::Analyzer*, zeek::packet_analysis::IP::SessionAdapter*> add_analyzer(
    zeek::Connection* conn, const zeek::Tag& analyzer_tag) {
    auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn);
    auto* pia = new zeek::analyzer::pia::PIA_TCP(conn);
    auto a = zeek::analyzer_mgr->InstantiateAnalyzer(analyzer_tag, conn);
    tcp->AddChildAnalyzer(a);
    tcp->AddChildAnalyzer(pia->AsAnalyzer());
    conn->SetSessionAdapter(tcp, pia);

    return {a, tcp};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static auto analyzer_tag = zeek::analyzer_mgr->GetComponentTag(FUZZ_ANALYZER_NAME);
    if ( ! analyzer_tag ) {
        std::fprintf(stderr, "Unable to find component tag for '%s'", FUZZ_ANALYZER_NAME);
        abort();
    }

    // Would be nice to have that in LLVMFuzzerInitialize, oh well...
    static bool one_time_setup = false;
    if ( ! one_time_setup ) {
        zeek::analyzer_mgr->DisableAllAnalyzers();
        zeek::analyzer_mgr->EnableAnalyzer(analyzer_tag);
        const auto& pia_tcp_tag = zeek::analyzer_mgr->GetComponentTag("PIA_TCP");
        zeek::analyzer_mgr->EnableAnalyzer(pia_tcp_tag);
        one_time_setup = true;
    }

    zeek::detail::FuzzBuffer fb{data, size};

    if ( ! fb.Valid() )
        return 0;

    auto conn = add_connection();
    if ( new_connection )
        conn->Event(new_connection, nullptr);

    auto [a, adapter] = add_analyzer(conn, analyzer_tag);

    // WebSocket specific initialization. May also want to fuzz
    // this in the future.
    static const auto& config_type = zeek::id::find_type<zeek::RecordType>("WebSocket::AnalyzerConfig");
    static const auto& config_rec = zeek::make_intrusive<zeek::RecordVal>(config_type);
    auto wsa = static_cast<zeek::analyzer::websocket::WebSocket_Analyzer*>(a);
    wsa->Configure(config_rec);

    for ( ;; ) {
        auto chunk = fb.Next();

        if ( ! chunk )
            break;

        try {
            a->NextStream(chunk->size, chunk->data.get(), chunk->is_orig);
        } catch ( const binpac::Exception& e ) {
        }

        chunk = {}; // Release buffer before draining events.
        zeek::event_mgr.Drain();

        // Has the analyzer been disabled during event processing?
        if ( ! adapter->HasChildAnalyzer(analyzer_tag) )
            break;
    }

    zeek::event_mgr.Drain();
    zeek::detail::fuzzer_cleanup_one_input();

    return 0;
}
