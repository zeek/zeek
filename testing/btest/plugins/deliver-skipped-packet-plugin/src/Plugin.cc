#include "Plugin.h"

#include <cstdio>
#include <cstring>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace {
class Foo : public zeek::analyzer::Analyzer {
public:
    Foo(zeek::Connection* conn) : zeek::analyzer::Analyzer("FOO", conn) {}

    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip,
                       int caplen) override {
        std::printf("Deliver Packet len=%d orig=%d\n", len, orig);
    }

    void DeliverSkippedPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip,
                              int caplen) override {
        std::printf("DeliverSkippedPacket len=%d orig=%d\n", len, orig);
    }

    static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn) { return new Foo(conn); }
};
} // namespace


namespace btest::plugin::Demo_Hooks {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE);

    AddComponent(new zeek::analyzer::Component("Foo", Foo::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Demo::Hooks";
    config.description = "Custom analyzer for all connections";
    config.version = {1, 0, 0};
    return config;
}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn) {
    auto* analyzer = zeek::analyzer_mgr->InstantiateAnalyzer("FOO", conn);

    if ( ! analyzer )
        zeek::reporter->FatalError("could not instantiate analyzer");

    if ( conn->ConnTransport() == TRANSPORT_TCP ) {
        // Need to use AddChildPacketAnalyzer() for TCP packet analyzers,
        // otherwise we only see packets if there's no reassembly.
        auto* adapter = static_cast<zeek::packet_analysis::TCP::TCPSessionAdapter*>(conn->GetSessionAdapter());
        adapter->AddChildPacketAnalyzer(analyzer);
    }
    else {
        auto* adapter = conn->GetSessionAdapter();
        adapter->AddChildAnalyzer(analyzer);
    }

    // Init the uid for GetUID()
    conn->GetVal();

    std::printf("Analyzer added to %s\n", conn->GetUID().Base62().c_str());
}

} // namespace btest::plugin::Demo_Hooks
