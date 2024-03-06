#include "zeek/cluster/Manager.h"

#include "zeek/Reporter.h"

using namespace zeek::cluster;

Manager::Manager()
    : backends(plugin::ComponentManager<BackendComponent>("Cluster", "ClusterBackendTag")),
      serializers(plugin::ComponentManager<SerializerComponent>("Cluster", "ClusterSerializerTag")) {}

Backend* Manager::InstantiateBackend(const zeek::EnumValPtr& tag, Serializer* serializer) {
    const BackendComponent* c = Backends().Lookup(tag);
    return c ? c->Factory()(serializer) : nullptr;
}

Serializer* Manager::InstantiateSerializer(const zeek::EnumValPtr& tag) {
    const SerializerComponent* c = Serializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}
