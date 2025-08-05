#include "Plugin.h"

#include <cstdio>
#include <cstring>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace {
class MyTapAnalyzer : public zeek::packet_analysis::TapAnalyzer {
public:
    MyTapAnalyzer(zeek::Connection* conn) : conn(conn) {}

    void TapPacket(const zeek::Packet& pkt, zeek::packet_analysis::PacketAction action,
                   const zeek::packet_analysis::SkipReason skip_reason) override {
        std::printf("Packet(len=%d orig=%d, action=%d skip_reason=%d) uid=%s\n", pkt.len, pkt.is_orig,
                    static_cast<int>(action), static_cast<int>(skip_reason), conn->GetUID().Base62().c_str());
    }

    void Init() override { std::printf("Init() uid=%s\n", conn->GetUID().Base62().c_str()); }

    void Done() override { std::printf("Done() uid=%s\n", conn->GetUID().Base62().c_str()); }

private:
    zeek::Connection* conn = nullptr;
};
} // namespace


namespace btest::plugin::Demo_TapAnalyzer {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE);

    zeek::plugin::Configuration config;
    config.name = "Demo::TapAnalyzer";
    config.description = "Testing the TapAnalyzer";
    config.version = {1, 0, 0};
    return config;
}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn) {
    // Init the uid for GetUID()
    conn->GetVal();

    auto analyzer = std::make_unique<MyTapAnalyzer>(conn);

    auto* adapter = conn->GetSessionAdapter();
    adapter->AddTapAnalyzer(std::move(analyzer));


    std::printf("Analyzer added to %s\n", conn->GetUID().Base62().c_str());
}

} // namespace btest::plugin::Demo_TapAnalyzer
