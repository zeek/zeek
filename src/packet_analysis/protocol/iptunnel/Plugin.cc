// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

namespace zeek::plugin::Zeek_IPTunnel {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::packet_analysis::Component("IPTunnel",
                                                 zeek::packet_analysis::IPTunnel::IPTunnelAnalyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::IPTunnel";
        config.description = "IPTunnel packet analyzer";
        return config;
    }

} plugin;

} // namespace zeek::plugin::Zeek_IPTunnel
