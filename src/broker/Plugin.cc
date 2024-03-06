#include "Plugin.h"

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Component.h"

using namespace zeek::plugin::Zeek_Cluster_Backend_Broker;

zeek::plugin::Configuration Plugin::Configure() {
    // Currently, there's always the broker_mgr instance that's explicitly
    // instantiate, so don't even allow to instantiate a second one via this
    // mechanism. In the future, *maybe* this could be enabled.
    auto fail_instantiate = [](cluster::Serializer*) -> cluster::Backend* {
        zeek::reporter->FatalError("do not instantiate broker explicitly");
        return nullptr;
    };

    AddComponent(new cluster::BackendComponent("BROKER", fail_instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Backend_Broker";
    config.description = "Cluster backend using Broker";
    return config;
}
