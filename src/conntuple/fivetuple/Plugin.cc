// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conntuple/Builder.h"
#include "zeek/conntuple/Component.h"

namespace zeek::plugin::Zeek_Conntuple_Fivetuple {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() {
        // The conntuple::Builder already has the default five-tuple behavior.
        AddComponent(new conntuple::Component("Fivetuple", zeek::conntuple::Builder::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Conntuple_Fivetuple";
        config.description = "Conntuple builder for Zeek's default five-tuples";
        return config;
    }
};

Plugin plugin;

} // namespace zeek::plugin::Zeek_Conntuple_Fivetuple
