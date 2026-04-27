// See the file "COPYING" in the main distribution directory for copyright.

#include "Plugin.h"

#include <memory>

#include "zeek/cluster/Component.h"

#include "Serializer.h"

using namespace zeek::cluster;

namespace zeek::plugin::Sans_Broker_Serializer {

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new EventSerializerComponent("SANS_BROKER_BIN_V1", []() -> std::unique_ptr<EventSerializer> {
        return std::make_unique<cluster::detail::SansBrokerBinV1_Serializer>();
    }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Sans_Broker_Serializer";
    config.description = "Broker event serialization bin/v1 re-implemented in Zeek";
    return config;
}


// Definition of the plugin.
Plugin plugin;

} // namespace zeek::plugin::Sans_Broker_Serializer
