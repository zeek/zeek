// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <memory>

#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/websocket/WebSocket.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek::cluster {

namespace detail {

/**
 * Iterate over all global variables and report these with
 * &broker_store or &backend attributes as non functional.
 *
 * Only call this if Cluster::backend is not Broker and not None.
 *
 * Remove in v9.1: The &backend and &broker_store attributes should be gone.
 */
void report_non_functional_broker_tables(const zeek::EnumValPtr& cluster_backend_val);

} // namespace detail

/**
 * Manager to allow registration of cluster components.
 *
 * This manager holds three component manager for event and log serializers
 * components, as well as backend components themselves.
 */
class Manager {
public:
    Manager();
    ~Manager();

    /**
     * Terminate the cluster manager.
     *
     * This shuts down any WebSocket servers that were started
     * at termination time.
     */
    void Terminate();

    /**
     * Instantiate a cluster backend with the given enum value and
     * pre-instantiated event and log serializers.
     *
     * @param tag The enum value identifying the backend.
     * @param event_serializer The event serializer to inject.
     * @param log_serializer The log serializer to inject.
     * @param event_handling_strategy The event handling strategy to inject.
     *
     * @return New ClusterBackend instance, or null if there's no such component.
     */
    std::unique_ptr<Backend> InstantiateBackend(const EnumValPtr& tag,
                                                std::unique_ptr<EventSerializer> event_serializer,
                                                std::unique_ptr<LogSerializer> log_serializer,
                                                std::unique_ptr<detail::EventHandlingStrategy> event_handling_strategy);

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

    /**
     * Start a WebSocket server for the given address and port pair.
     *
     * @param options The options to use for the WebSocket server.
     *
     * @return True on success, else false.
     */
    bool ListenWebSocket(const websocket::detail::ServerOptions& options);

private:
    plugin::ComponentManager<BackendComponent> backends;
    plugin::ComponentManager<EventSerializerComponent> event_serializers;
    plugin::ComponentManager<LogSerializerComponent> log_serializers;

    using WebSocketServerKey = std::pair<std::string, uint16_t>;
    struct WebSocketServerEntry {
        websocket::detail::ServerOptions options;
        std::unique_ptr<websocket::detail::WebSocketServer> server;
    };
    std::map<WebSocketServerKey, WebSocketServerEntry> websocket_servers;
};

// This manager instance only exists for plugins to register components,
// not for actual cluster functionality.
extern Manager* manager;

} // namespace zeek::cluster
