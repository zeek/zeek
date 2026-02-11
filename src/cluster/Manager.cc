// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Manager.h"

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/websocket/WebSocket.h"
#include "zeek/util.h"

using namespace zeek::cluster;

void detail::report_non_functional_broker_tables(const zeek::EnumValPtr& cluster_backend_val) {
    auto broker_backend_val = zeek::id::find_val<zeek::EnumVal>("Cluster::CLUSTER_BACKEND_BROKER");
    assert(cluster_backend_val != broker_backend_val);

    const auto& globals = zeek::detail::global_scope()->Vars();
    std::string x509_known_log_certs_with_broker = "X509::known_log_certs_with_broker";

    for ( const auto& [name, id] : globals ) {
        if ( ! id->HasVal() )
            continue;

        // Remove in v9.1: This one is only used when a deprecated option is
        // set that will only work with Broker anyhow. Not overthinking this.
        if ( id->Name() == x509_known_log_certs_with_broker )
            continue;

        const char* what = nullptr;

        if ( id->GetAttr(zeek::detail::ATTR_BACKEND) )
            what = "&backend";
        else if ( id->GetAttr(zeek::detail::ATTR_BROKER_STORE) )
            what = "&broker_store";

        if ( ! what )
            continue;

        id->Error(util::fmt("table %s uses Broker-specific attribute %s, but non-Broker backend %s selected",
                            id->Name(), what, obj_desc_short(cluster_backend_val).c_str()));
    }
}

Manager::Manager()
    : backends(plugin::ComponentManager<BackendComponent>("Cluster", "BackendTag")),
      event_serializers(plugin::ComponentManager<EventSerializerComponent>("Cluster", "EventSerializerTag")),
      log_serializers(plugin::ComponentManager<LogSerializerComponent>("Cluster", "LogSerializerTag")) {}

// Force destructor definition into compilation unit to avoid needing the
// full websocket::Server declaration in cluster/Manager.h.
Manager::~Manager() = default;

void Manager::Terminate() {
    for ( const auto& [_, entry] : websocket_servers )
        entry.server->Terminate();
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

bool Manager::ListenWebSocket(const websocket::detail::ServerOptions& options) {
    WebSocketServerKey key{options.host, options.port};

    if ( websocket_servers.count(key) != 0 ) {
        const auto& entry = websocket_servers[key];
        if ( entry.options == options )
            return true;

        zeek::emit_builtin_error(zeek::util::fmt("Already listening on %s:%d", options.host.c_str(), options.port));
        return false;
    }

    std::string ident = util::fmt("%s:%d", options.host.c_str(), options.port);

    auto dispatcher =
        std::make_unique<websocket::detail::WebSocketEventDispatcher>(std::move(ident), options.max_event_queue_size);
    auto server = websocket::detail::StartServer(std::move(dispatcher), options);

    if ( ! server )
        return false;

    websocket_servers.insert({key, WebSocketServerEntry{options, std::move(server)}});
    return true;
}
