// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/vntag/VNTag.h"

namespace zeek::plugin::Zeek_VNTag {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("VNTag", zeek::packet_analysis::VNTag::VNTagAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::VNTag";
        config.description = "VNTag packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_VNTag
