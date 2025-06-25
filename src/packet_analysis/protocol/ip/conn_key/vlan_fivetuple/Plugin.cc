// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conn_key/Component.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/vlan_fivetuple/Factory.h"

namespace zeek::plugin::Zeek_ConnKey_VLAN {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new conn_key::Component("VLAN_FIVETUPLE", zeek::conn_key::vlan_fivetuple::Factory::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::ConnKey_Vlan_Fivetuple";
        config.description = "ConnKey factory for 802.1Q VLAN/Q-in-Q + IP/port/proto five-tuples";
        return config;
    }
};

Plugin plugin;

} // namespace zeek::plugin::Zeek_ConnKey_VLAN
