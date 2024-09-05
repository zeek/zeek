#include "zeek/cluster/Manager.h"

#include "zeek/cluster/Serializer.h"

using namespace zeek::cluster;

Manager::Manager()
    : backends(plugin::ComponentManager<BackendComponent>("Cluster", "ClusterBackendTag")),
      event_serializers(plugin::ComponentManager<EventSerializerComponent>("Cluster", "EventSerializerTag")),
      log_serializers(plugin::ComponentManager<LogSerializerComponent>("Cluster", "LogSerializerTag")) {}

Backend* Manager::InstantiateBackend(const zeek::EnumValPtr& tag, EventSerializer* event_serializer,
                                     LogSerializer* log_serializer) {
    const BackendComponent* c = Backends().Lookup(tag);
    return c ? c->Factory()(event_serializer, log_serializer) : nullptr;
}

EventSerializer* Manager::InstantiateEventSerializer(const zeek::EnumValPtr& tag) {
    const EventSerializerComponent* c = EventSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}

LogSerializer* Manager::InstantiateLogSerializer(const zeek::EnumValPtr& tag) {
    const LogSerializerComponent* c = LogSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}
