#include "zeek/cluster/Manager.h"

#include "zeek/cluster/Serializer.h"

using namespace zeek::cluster;

Manager::Manager()
    : backends(plugin::ComponentManager<BackendComponent>("Cluster", "ClusterBackendTag")),
      event_serializers(plugin::ComponentManager<EventSerializerComponent>("Cluster", "EventSerializerTag")),
      log_serializers(plugin::ComponentManager<LogSerializerComponent>("Cluster", "LogSerializerTag")) {}

Backend* Manager::InstantiateBackend(const zeek::EnumValPtr& tag, std::unique_ptr<EventSerializer> event_serializer,
                                     std::unique_ptr<LogSerializer> log_serializer) {
    const BackendComponent* c = Backends().Lookup(tag);
    return c ? c->Factory()(std::move(event_serializer), std::move(log_serializer)) : nullptr;
}

std::unique_ptr<EventSerializer> Manager::InstantiateEventSerializer(const zeek::EnumValPtr& tag) {
    const EventSerializerComponent* c = EventSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}

std::unique_ptr<LogSerializer> Manager::InstantiateLogSerializer(const zeek::EnumValPtr& tag) {
    const LogSerializerComponent* c = LogSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}
