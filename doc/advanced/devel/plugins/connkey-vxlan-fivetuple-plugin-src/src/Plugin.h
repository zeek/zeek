
#pragma once

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace Zeek_ConnKey_Vxlan_Vni_Fivetuple {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace Zeek_ConnKey_Vxlan_Vni_Fivetuple
} // namespace plugin
