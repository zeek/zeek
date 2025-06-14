// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conntuple/Component.h"
#include "zeek/conntuple/fivetuple/Factory.h"

namespace zeek::plugin::Zeek_Conntuple_Fivetuple {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() {
        AddComponent(new conntuple::Component("Fivetuple", zeek::conntuple::fivetuple::Factory::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Conntuple_Fivetuple";
        config.description = "Conntuple factory for Zeek's default IP/port/proto five-tuples";
        return config;
    }
};

Plugin plugin;

} // namespace zeek::plugin::Zeek_Conntuple_Fivetuple
