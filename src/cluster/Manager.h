// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek::cluster {

/**
 * Manager to allow registration of cluster components.
 *
 * This manager holds three component manager for event and log serializers
 * components, as well as backend components themselves.
 */
class Manager {
public:
    Manager();

    /**
     * Instantiate a cluster backend with the given enum value and
     * pre-instantiated event and log serializers.
     *
     * @param tag The enum value identifying the backend.
     * @param event_serializer The event serializer to inject.
     * @param log_serializer The log serializer to inject.
     *
     * @return New ClusterBackend instance, or null if there's no such component.
     */
    std::unique_ptr<Backend> InstantiateBackend(const EnumValPtr& tag,
                                                std::unique_ptr<EventSerializer> event_serializer,
                                                std::unique_ptr<LogSerializer> log_serializer);

    /**
     * Instantiate a event serializer with the given enum value.
     *
     * @param tag The enum value identifying a serializer.
     *
     * @return New Serializer instance, or null if there's no such component.
     */
    std::unique_ptr<EventSerializer> InstantiateEventSerializer(const EnumValPtr& tag);

    /**
     * Instantiate a log serializer with the given enum value.
     *
     * @param tag The enum value identifying a serializer.
     *
     * @return New Serializer instance, or null if there's no such component.
     */
    std::unique_ptr<LogSerializer> InstantiateLogSerializer(const EnumValPtr& tag);

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

// This manager instance only exists for plugins to register components,
// not for actual cluster functionality.
extern Manager* manager;

} // namespace zeek::cluster
