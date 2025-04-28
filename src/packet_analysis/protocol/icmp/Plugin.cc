// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/icmp/ICMP.h"

namespace zeek::plugin::Zeek_ICMP {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("ICMP", zeek::packet_analysis::ICMP::ICMPAnalyzer::Instantiate));
        AddComponent(new zeek::analyzer::Component("ICMP", nullptr, 0, true, false, true));

        zeek::plugin::Configuration config;
        config.name = "Zeek::ICMP";
        config.description = "Packet analyzer for ICMP";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_ICMP
