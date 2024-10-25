#include "Plugin.h"

#include <memory>

#include "zeek/cluster/Component.h"

#include "Serializer.h"

using namespace zeek::cluster;
using namespace zeek::plugin::Broker_Serializer;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new EventSerializerComponent("BROKER_BIN_V1", []() -> std::unique_ptr<EventSerializer> {
        return std::make_unique<cluster::detail::BrokerBinV1_Serializer>();
    }));
    AddComponent(new EventSerializerComponent("BROKER_JSON_V1", []() -> std::unique_ptr<EventSerializer> {
        return std::make_unique<cluster::detail::BrokerJsonV1_Serializer>();
    }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Broker_Serializer";
    config.description = "Event serialization using Broker event formats (binary and json)";
    return config;
}
