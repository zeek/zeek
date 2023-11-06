// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/pbb/PBB.h"

namespace zeek::plugin::Zeek_PBB {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::packet_analysis::Component("PBB", zeek::packet_analysis::PBB::PBBAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::PBB";
        config.description = "PBB packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_PBB
