// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/l2tp/L2TP.h"

namespace zeek::plugin::Zeek_L2TP {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("L2TP", zeek::packet_analysis::L2TP::L2TPAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::L2TP";
        config.description = "L2TP packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_L2TP
