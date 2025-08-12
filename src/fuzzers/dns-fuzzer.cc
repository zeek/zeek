// See the file "COPYING" in the main distribution directory for copyright.

#include <binpac.h>

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/conn_key/Manager.h"
#include "zeek/fuzzers/fuzzer-setup.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/session/Manager.h"

static constexpr auto ZEEK_FUZZ_ANALYZER = "dns";

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

static zeek::analyzer::Analyzer* add_analyzer(zeek::Connection* conn) {
    auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn);
    auto* pia = new zeek::analyzer::pia::PIA_TCP(conn);
    auto a = zeek::analyzer_mgr->InstantiateAnalyzer(ZEEK_FUZZ_ANALYZER, conn);
    tcp->AddChildAnalyzer(a);
    tcp->AddChildAnalyzer(pia->AsAnalyzer());
    conn->SetSessionAdapter(tcp, pia);
    return a;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto conn = add_connection();
    auto a = add_analyzer(conn);

    // The conn protocol scripts assume that new_connection is run before connection_state_remove.
    if ( new_connection )
        conn->Event(new_connection, nullptr);

    try {
        a->DeliverPacket(size, data, true, -1, nullptr, size);
    } catch ( const binpac::Exception& e ) {
    }

    zeek::event_mgr.Drain();
    zeek::detail::fuzzer_cleanup_one_input();
    return 0;
}
