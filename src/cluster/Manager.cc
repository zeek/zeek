// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Manager.h"

#include "zeek/Func.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/websocket/WebSocket.h"
#include "zeek/util.h"

using namespace zeek::cluster;

Manager::Manager()
    : backends(plugin::ComponentManager<BackendComponent>("Cluster", "BackendTag")),
      event_serializers(plugin::ComponentManager<EventSerializerComponent>("Cluster", "EventSerializerTag")),
      log_serializers(plugin::ComponentManager<LogSerializerComponent>("Cluster", "LogSerializerTag")) {}

// Force destructor definition into compilation unit to avoid needing the
// full websocket::Server declaration in cluster/Manager.h.
Manager::~Manager() = default;

void Manager::Terminate() {
    for ( const auto& [_, server] : websocket_servers )
        server->Terminate();
}

std::unique_ptr<Backend> Manager::InstantiateBackend(
    const zeek::EnumValPtr& tag, std::unique_ptr<EventSerializer> event_serializer,
    std::unique_ptr<LogSerializer> log_serializer,
    std::unique_ptr<detail::EventHandlingStrategy> event_handling_strategy) {
    if ( const auto* c = Backends().Lookup(tag) )
        return c->Factory()(std::move(event_serializer), std::move(log_serializer), std::move(event_handling_strategy));

    return nullptr;
}

std::unique_ptr<EventSerializer> Manager::InstantiateEventSerializer(const zeek::EnumValPtr& tag) {
    const EventSerializerComponent* c = EventSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}

std::unique_ptr<LogSerializer> Manager::InstantiateLogSerializer(const zeek::EnumValPtr& tag) {
    const LogSerializerComponent* c = LogSerializers().Lookup(tag);
    return c ? c->Factory()() : nullptr;
}

bool Manager::ListenWebSocket(const std::string& addr, int port, const cluster::websocket::TLSOptions& tls_options) {
    WebSocketServerKey key{addr, port};

    if ( websocket_servers.count(key) != 0 ) {
        zeek::emit_builtin_error(zeek::util::fmt("Already listening on %s:%d", addr.c_str(), port));
        return false;
    }

    auto server = websocket::StartServer(std::make_unique<websocket::WebSocketEventDispatcher>(),
                                         websocket::ServerOptions{addr, port}, tls_options);

    if ( ! server )
        return false;

    websocket_servers[key] = std::move(server);
    return true;
}
