#include "Plugin.h"

#include <cstdio>
#include <cstring>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace {
using SkipReason = zeek::packet_analysis::IP::detail::SkipReason;

class MyTapAnalyzer : public zeek::packet_analysis::IP::detail::TapAnalyzer {
public:
    MyTapAnalyzer(zeek::Connection* conn) : conn(conn) {}

    void DeliverPacket(const zeek::Packet& pkt) override {
        std::printf("DeliverPacket(len=%d orig=%d) uid=%s\n", pkt.len, pkt.is_orig, conn->GetUID().Base62().c_str());
    }

    void SkippedPacket(const zeek::Packet& pkt, SkipReason skip_reason) override {
        std::printf("SkippedPacket(len=%d orig=%d) uid=%s\n", pkt.len, pkt.is_orig, conn->GetUID().Base62().c_str());
    }

    void Done() override { std::printf("Done() uid=%s\n", conn->GetUID().Base62().c_str()); }

private:
    zeek::Connection* conn = nullptr;
};
} // namespace


namespace btest::plugin::Demo_Hooks {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE);

    zeek::plugin::Configuration config;
    config.name = "Demo::Hooks";
    config.description = "Testing the TapAnalyzer";
    config.version = {1, 0, 0};
    return config;
}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn) {
    auto analyzer = std::make_unique<MyTapAnalyzer>(conn);

    auto* adapter = conn->GetSessionAdapter();
    adapter->AddTapAnalyzer(std::move(analyzer));

    // Init the uid for GetUID()
    conn->GetVal();

    std::printf("Analyzer added to %s\n", conn->GetUID().Base62().c_str());
}

} // namespace btest::plugin::Demo_Hooks
