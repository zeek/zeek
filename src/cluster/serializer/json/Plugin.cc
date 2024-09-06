#include "Plugin.h"

#include "zeek/cluster/Component.h"
#include "zeek/cluster/serializer/json/Serializer.h"


using namespace zeek::plugin::JSONLines_Log_Serializer;
using namespace zeek::cluster;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new LogSerializerComponent("JSONLINES_V1", []() -> cluster::LogSerializer* {
        return new cluster::detail::JSONLinesLogSerializer();
    }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster::JSONLines";
    config.description = "Log record serialization into JSON Lines. No unserialization support.";
    return config;
}
