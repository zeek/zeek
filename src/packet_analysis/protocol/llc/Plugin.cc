// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/llc/LLC.h"

namespace zeek::plugin::Zeek_LLC {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::packet_analysis::Component("LLC", zeek::packet_analysis::LLC::LLCAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::LLC";
        config.description = "LLC packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_LLC
