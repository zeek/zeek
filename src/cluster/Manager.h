// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/cluster/Component.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek::cluster {

/**
 * This manager only exists to encapsulate registration of cluster backend components.
 */
class Manager {
public:
    Manager();

    /**
     * Instantiate a event serializer with the given enum value.

     * @param tag The enum value identifying a serializer.
     *
     * @return New Serializer instance, or null if there's no such component.
     */
    Serializer* InstantiateSerializer(const EnumValPtr& tag);

    /**
     * Instantiate a cluster backend with the given enum value.
     *
     * @return New ClusterBackend instance, or null if there's no such component.
     */
    Backend* InstantiateBackend(const EnumValPtr& tag, Serializer* serializer);

    /**
     * @return The ComponentManager for backends.
     */
    plugin::ComponentManager<BackendComponent>& Backends() { return backends; };

    /**
     * @return The ComponentManager for serializers.
     */
    plugin::ComponentManager<SerializerComponent>& Serializers() { return serializers; };

private:
    plugin::ComponentManager<BackendComponent> backends;
    plugin::ComponentManager<SerializerComponent> serializers;
};

// The manager is only here to allow plugins to register components. A ClusterBackend
// instance is what will actually do Publish(), Subscribe() and so forth.
extern Manager* manager;

} // namespace zeek::cluster
