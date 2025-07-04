// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conn_key/Component.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::plugin::Zeek_Conntuple_Fivetuple {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new conn_key::Component("Fivetuple", zeek::conn_key::fivetuple::Factory::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::ConnKey_Fivetuple";
        config.description = "ConnKey factory for Zeek's default IP/port/proto five-tuples";
        return config;
    }
};

Plugin plugin;

} // namespace zeek::plugin::Zeek_Conntuple_Fivetuple
