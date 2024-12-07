// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/broker/Plugin.h"

#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"

using namespace zeek::plugin::Zeek_Cluster_Backend_Broker;

zeek::plugin::Configuration Plugin::Configure() {
    // For now, there's always the broker_mgr instance that's explicitly
    // instantiated in zeek-setup.cc. Don't even allow to instantiate
    // a second one via the plugin mechanism. In the future, this could
    // be changed so that broker is instantiated on demand only.
    auto fail_instantiate = [](std::unique_ptr<cluster::EventSerializer>,
                               std::unique_ptr<cluster::LogSerializer>) -> std::unique_ptr<cluster::Backend> {
        zeek::reporter->FatalError("do not instantiate broker explicitly");
        return nullptr;
    };

    AddComponent(new cluster::BackendComponent("BROKER", fail_instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Backend_Broker";
    config.description = "Cluster backend using Broker";
    return config;
}
