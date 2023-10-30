// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

namespace zeek::plugin::Zeek_TCP {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::packet_analysis::Component("TCP", zeek::packet_analysis::TCP::TCPAnalyzer::Instantiate));
        AddComponent(new zeek::analyzer::Component("TCP", nullptr, 0, true, false, true));

        zeek::plugin::Configuration config;
        config.name = "Zeek::TCP_PKT";
        config.description = "Packet analyzer for TCP";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_TCP
