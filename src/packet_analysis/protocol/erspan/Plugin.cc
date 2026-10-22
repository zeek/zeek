// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/erspan/ERSPAN.h"

namespace zeek::plugin::Zeek_ERSPAN {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("ERSPAN", zeek::packet_analysis::ERSPAN::ERSPANAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::ERSPAN";
        config.description = "ERSPAN packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_ERSPAN
