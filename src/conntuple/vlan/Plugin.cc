// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conntuple/Component.h"
#include "zeek/conntuple/vlan/Builder.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() {
        AddComponent(new conntuple::Component("VLAN", zeek::plugin::Zeek_Conntuple_VLAN::Builder::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Conntuple_VLAN";
        config.description = "Conntuple builder for 802.1Q VLAN- and Q-in-Q-aware flows";
        return config;
    }
};

Plugin plugin;

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
