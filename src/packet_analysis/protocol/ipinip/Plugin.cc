// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ipinip/IPInIP.h"

namespace zeek::plugin::Zeek_IPInIP {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("IPINIP", zeek::packet_analysis::IPInIP::IPInIPAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::IPInIP";
        config.description = "IP-in-IP tunnel packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_IPInIP
