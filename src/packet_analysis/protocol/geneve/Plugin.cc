// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/geneve/Geneve.h"

namespace zeek::plugin::Zeek_Geneve {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("Geneve", zeek::packet_analysis::Geneve::GeneveAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Geneve";
        config.description = "Geneve packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_Geneve
