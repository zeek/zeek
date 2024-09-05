// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek::cluster {

/**
 * This manager only exists to encapsulate registration of cluster backend components.
 */
class Manager {
public:
    Manager();

    /**
     * Instantiate a cluster backend with the given enum value.
     *
     * @return New ClusterBackend instance, or null if there's no such component.
     */
    Backend* InstantiateBackend(const EnumValPtr& tag, EventSerializer* event_serializer,
                                LogSerializer* log_serializer);

    /**
     * Instantiate a event serializer with the given enum value.
     *
     * @param tag The enum value identifying a serializer.
     *
     * @return New Serializer instance, or null if there's no such component.
     */
    EventSerializer* InstantiateEventSerializer(const EnumValPtr& tag);

    /**
     * Instantiate a log serializer with the given enum value.
     *
     * @param tag The enum value identifying a serializer.
     *
     * @return New Serializer instance, or null if there's no such component.
     */
    LogSerializer* InstantiateLogSerializer(const EnumValPtr& tag);

    /**
     * @return The ComponentManager for backends.
     */
    plugin::ComponentManager<BackendComponent>& Backends() { return backends; };

    /**
     * @return The ComponentManager for event serializers.
     */
    plugin::ComponentManager<EventSerializerComponent>& EventSerializers() { return event_serializers; };

    /**
     * @return The ComponentManager for serializers.
     */
    plugin::ComponentManager<LogSerializerComponent>& LogSerializers() { return log_serializers; };

private:
    plugin::ComponentManager<BackendComponent> backends;
    plugin::ComponentManager<EventSerializerComponent> event_serializers;
    plugin::ComponentManager<LogSerializerComponent> log_serializers;
};

// The manager is only here to allow plugins to register components. A ClusterBackend
// instance is what will actually do Publish(), Subscribe() and so forth.
extern Manager* manager;

} // namespace zeek::cluster
