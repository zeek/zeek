
#include "Plugin.h"

#include <zeek/conn_key/Component.h>

#include "Factory.h"

namespace plugin {
namespace Zeek_ConnKey_Vxlan_Vni_Fivetuple {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::Zeek_ConnKey_Vxlan_Vni_Fivetuple;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::ConnKey_Vxlan_Vni_Fivetuple";
    config.description = "ConnKey implementation using the most outer VXLAN VNI";
    config.version = {0, 1, 0};

    AddComponent(new zeek::conn_key::Component("VXLAN_VNI_FIVETUPLE",
                                               zeek::conn_key::vxlan_vni_fivetuple::Factory::Instantiate));

    return config;
}
