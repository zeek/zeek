// See the file "COPYING" in the main distribution directory for copyright.

// Implement Broker's WebSocket client handling in Zeek.

#include "zeek/cluster/websocket/WebSocket.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string_view>
#include <variant>

#include "zeek/Reporter.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/BifSupport.h"
#include "zeek/cluster/Manager.h"
#include "zeek/cluster/OnLoop.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/Telemetry.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/cluster/websocket/Plugin.h"
#include "zeek/cluster/websocket/events.bif.h"
#include "zeek/net_util.h"
#include "zeek/threading/MsgThread.h"

#include "broker/data_envelope.hh"
#include "broker/error.hh"
#include "broker/format/json.hh"
#include "broker/zeek.hh"
#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define WS_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Cluster_WebSocket::plugin, __VA_ARGS__)

namespace zeek {
const char* zeek_version();
}

using namespace zeek::cluster::websocket::detail;

namespace {

class WebSocketEventHandlingStrategy : public zeek::cluster::detail::EventHandlingStrategy {
public:
    WebSocketEventHandlingStrategy(std::shared_ptr<WebSocketClient> ws, WebSocketEventDispatcher* dispatcher)
        : wsc(std::move(ws)), dispatcher(dispatcher) {}

private:
    /**
     * Any received remote event is encoded into Broker's JSON v1 format and
     * send over to the WebSocket client.
     *
     * We leverage low-level Broker encoding functions here directly. This
     * will need some abstractions if client's can opt to use different encodings
     * of events in the future.
     */
    bool DoProcessEvent(std::string_view topic, zeek::cluster::Event e) override {
        // If the client has left, no point in sending it any pending event.
        if ( wsc->IsTerminated() )
            return true;


        // Any events received from the backend before an Ack was sent
        // are discarded.
        if ( ! wsc->IsAcked() )
            return true;

        // XXX The serialization is somewhat slow, it would be good to offload
        // it to a thread, or try to go from Val's directly to JSON and see
        // if that's faster.
        auto ev = zeek::cluster::detail::to_broker_event(e);
        if ( ! ev ) {
            fprintf(stderr, "[ERROR] Unable to go from cluster::Event to broker::event\n");
            return false;
        }

        buffer.clear();
        auto envelope = broker::data_envelope::make(topic, ev->as_data());
        broker::format::json::v1::encode(envelope, std::back_inserter(buffer));

        dispatcher->QueueReply(WebSocketSendReply{wsc, buffer});
        return true;
    }

    /**
     * Events from backends aren't enqueued into the event loop when
     * running for WebSocket clients.
     */
    void DoProcessLocalEvent(zeek::EventHandlerPtr h, zeek::Args args) override {}

    /**
     * Send errors directly to the client.
     */
    void DoProcessError(std::string_view tag, std::string_view message) override {
        // Just send out the error.
        wsc->SendError(tag, message);
    }

    std::string buffer;
    std::shared_ptr<WebSocketClient> wsc;
    WebSocketEventDispatcher* dispatcher;
};

class ReplyInputMessage : public zeek::threading::BasicInputMessage {
public:
    ReplyInputMessage(WebSocketReply work) : zeek::threading::BasicInputMessage("ReplyInput"), work(std::move(work)) {};
    bool Process() override {
        return std::visit([this](auto& item) -> bool { return Process(item); }, work);
    };

private:
    bool Process(const WebSocketSendReply& sr) {
        const auto& wsc = sr.wsc;
        if ( wsc->IsTerminated() )
            return true;

        auto send_info = wsc->SendText(sr.msg);
        if ( ! send_info.success && ! wsc->IsTerminated() )
            fprintf(stderr, "[ERROR] Failed to send reply to WebSocket client %s (%s:%d)\n", wsc->getId().c_str(),
                    wsc->getRemoteIp().c_str(), wsc->getRemotePort());

        return true;
    }

    bool Process(const WebSocketCloseReply& cr) {
        const auto& wsc = cr.wsc;
        if ( ! wsc->IsTerminated() )
            wsc->Close(cr.code, cr.reason);

        return true;
    }

    WebSocketReply work;
};

} // namespace


// Inspired by broker/internal/json_client.cc
WebSocketClient::SendInfo WebSocketClient::SendError(std::string_view tag, std::string_view message) {
    std::string buf;
    buf.reserve(tag.size() + message.size() + 32);
    auto out = std::back_inserter(buf);
    *out++ = '{';
    broker::format::json::v1::append_field("type", "error", out);
    *out++ = ',';
    broker::format::json::v1::append_field("code", tag, out);
    *out++ = ',';
    broker::format::json::v1::append_field("context", message, out);
    *out++ = '}';
    return SendText(buf);
}

// Inspired by broker/internal/json_client.cc
WebSocketClient::SendInfo WebSocketClient::SendAck(std::string_view endpoint, std::string_view version) {
    std::string buf;
    buf.reserve(endpoint.size() + version.size() + 32);
    auto out = std::back_inserter(buf);
    *out++ = '{';
    broker::format::json::v1::append_field("type", "ack", out);
    *out++ = ',';
    broker::format::json::v1::append_field("endpoint", endpoint, out);
    *out++ = ',';
    broker::format::json::v1::append_field("version", version, out);
    *out++ = '}';
    auto r = SendText(buf);
    acked = true;
    return r;
}

void WebSocketClient::SetSubscriptions(const std::vector<std::string>& topic_prefixes) {
    for ( const auto& topic_prefix : topic_prefixes )
        subscriptions_state[topic_prefix] = false;
}

void WebSocketClient::SetSubscriptionActive(const std::string& topic_prefix) {
    if ( ! subscriptions_state.contains(topic_prefix) ) {
        zeek::reporter->InternalWarning("Unknown topic_prefix for WebSocket client %s!", topic_prefix.c_str());
        return;
    }

    subscriptions_state[topic_prefix] = true;
}

bool WebSocketClient::AllSubscriptionsActive() const {
    for ( const auto& [_, status] : subscriptions_state ) {
        if ( ! status )
            return false;
    }

    return true;
}

const std::vector<std::string> WebSocketClient::GetSubscriptions() const {
    std::vector<std::string> subs;
    subs.reserve(subscriptions_state.size());

    for ( const auto& [topic, _] : subscriptions_state )
        subs.emplace_back(topic);

    return subs;
}

class zeek::cluster::websocket::detail::ReplyMsgThread : public zeek::threading::MsgThread {
public:
    ReplyMsgThread() : zeek::threading::MsgThread() { SetName("ws-reply-thread"); }

    void Run() override {
        zeek::util::detail::set_thread_name("zk/ws-reply-thread");
        MsgThread::Run();
    }

    bool OnHeartbeat(double network_time, double current_time) override { return true; }

    bool OnFinish(double network_time) override { return true; }
};

WebSocketEventDispatcher::WebSocketEventDispatcher(std::string ident, size_t queue_size) {
    onloop =
        new zeek::detail::OnLoopProcess<WebSocketEventDispatcher, WebSocketEvent>(this,
                                                                                  "WebSocketEventDispatcher:" + ident,
                                                                                  queue_size);
    // Register the onloop instance the IO loop. Lifetime will be managed by the loop.
    onloop->Register(false);

    reply_msg_thread = new ReplyMsgThread();
    reply_msg_thread->Start();
}

WebSocketEventDispatcher::~WebSocketEventDispatcher() {
    // Freed by threading manager.
    reply_msg_thread = nullptr;
}

void WebSocketEventDispatcher::Terminate() {
    WS_DEBUG("Terminating WebSocketEventDispatcher");

    for ( auto& [_, client] : clients ) {
        const auto& wsc = client.wsc;
        const auto& backend = client.backend;
        WS_DEBUG("Sending close to WebSocket client %s (%s:%d)", wsc->getId().c_str(), wsc->getRemoteIp().c_str(),
                 wsc->getRemotePort());

        QueueReply(WebSocketCloseReply{wsc, 1001, "Terminating"});

        if ( backend )
            backend->Terminate();
    }

    clients.clear();

    onloop->Close();

    // Wait for the reply_msg_thread to process any outstanding
    // WebSocketReply messages before returning.
    reply_msg_thread->SignalStop();
    reply_msg_thread->WaitForStop();
}

void WebSocketEventDispatcher::QueueForProcessing(WebSocketEvent&& event) {
    // Just delegate to onloop. The work will be done in Process()
    onloop->QueueForProcessing(std::move(event));
}

void WebSocketEventDispatcher::QueueReply(WebSocketReply&& reply) {
    // Delegate to the reply thread.
    reply_msg_thread->SendIn(new ReplyInputMessage(std::move(reply)));
}

// Process a WebSocketEvent message on the Zeek IO loop.
void WebSocketEventDispatcher::Process(const WebSocketEvent& event) {
    std::visit([this](auto&& arg) { Process(arg); }, event);
}

void WebSocketEventDispatcher::Process(const WebSocketOpen& open) {
    const auto& wsc = open.wsc;
    const auto& id = open.id;
    const auto& it = clients.find(id);
    if ( it != clients.end() ) {
        // This shouldn't happen!
        reporter->Error("Open for existing WebSocket client with id %s!", id.c_str());
        QueueReply(WebSocketCloseReply{wsc, 1001, "Internal error"});
        return;
    }

    // As of now, terminate clients coming to anything other than /v1/messages/json.
    if ( open.uri != "/v1/messages/json" ) {
        open.wsc->SendError("invalid_uri", "Invalid URI - use /v1/messages/json");
        open.wsc->Close(1008, "Invalid URI - use /v1/messages/json");

        // Still create an entry as we might see messages and close events coming in.
        clients[id] = WebSocketClientEntry{id, wsc, nullptr};
        return;
    }

    std::string application_name = open.application_name.value_or("unknown");

    // A bit ad-hoc
    bool good_application_name = std::ranges::all_of(application_name, [](auto c) {
        return std::isalnum(c) || c == '/' || c == '_' || c == '-' || c == '.' || c == '=' || c == ':' || c == '*' ||
               c == '@';
    });

    if ( ! good_application_name ) {
        open.wsc->SendError("invalid_application_name", "Invalid X-Application-Name");
        open.wsc->Close(1008, "Invalid X-Application-Name");

        // Still create an entry as we might see messages and close events coming in.
        clients[id] = WebSocketClientEntry{id, wsc, nullptr};
        return;
    }

    // Generate an ID for this client.
    auto ws_id = cluster::backend->NodeId() + "-websocket-" + id;

    // If the globally configured backend is CLUSTER_BACKEND_BROKER, then switch
    // the WebSocket client's backend to CLUSTER_BACKEND_BROKER_WEBSOCKET_SHIM
    // so that pub/sub is using the local broker endpoint via its hub functionality
    // instead of instantiating a new Broker manager.
    static const auto& event_serializer_val = id::find_val<zeek::EnumVal>("Cluster::event_serializer");
    auto event_serializer = cluster::manager->InstantiateEventSerializer(event_serializer_val);
    static const auto& cluster_backend_val = id::find_val<zeek::EnumVal>("Cluster::backend");
    auto effective_backend_val = cluster_backend_val;

    static const auto& broker_enum_val = zeek::id::find_val<EnumVal>("Cluster::CLUSTER_BACKEND_BROKER");
    static const auto& broker_ws_shim_enum_val =
        zeek::id::find_val<EnumVal>("Cluster::CLUSTER_BACKEND_BROKER_WEBSOCKET_SHIM");
    if ( effective_backend_val == broker_enum_val ) {
        WS_DEBUG("Using broker websocket shim");
        effective_backend_val = broker_ws_shim_enum_val;
    }

    auto event_handling_strategy = std::make_unique<WebSocketEventHandlingStrategy>(wsc, this);
    auto backend = zeek::cluster::manager->InstantiateBackend(effective_backend_val, std::move(event_serializer),
                                                              nullptr, std::move(event_handling_strategy));

    if ( ! backend ) {
        reporter->Error("Failed to instantiate backend for client with id %s!", id.c_str());
        QueueReply(WebSocketCloseReply{wsc, 1001, "Internal error"});
        return;
    }

    cluster::detail::configure_backend_telemetry(*backend, "websocket", {{"app", application_name}});

    WS_DEBUG("New WebSocket client %s (%s:%d) - using id %s backend=%p", id.c_str(), wsc->getRemoteIp().c_str(),
             wsc->getRemotePort(), ws_id.c_str(), backend.get());

    // XXX: We call InitPostScript to populate member vars required for connectivity.
    backend->InitPostScript();
    backend->Init(std::move(ws_id));

    clients[id] = WebSocketClientEntry{id, wsc, std::move(backend), open.application_name};
}

void WebSocketEventDispatcher::Process(const WebSocketClose& close) {
    const auto& id = close.id;
    const auto& it = clients.find(id);

    if ( it == clients.end() ) {
        reporter->Error("Close from non-existing WebSocket client with id %s!", id.c_str());
        return;
    }

    auto& wsc = it->second.wsc;
    auto& backend = it->second.backend;

    WS_DEBUG("Close from client %s (%s:%d) backend=%p", wsc->getId().c_str(), wsc->getRemoteIp().c_str(),
             wsc->getRemotePort(), backend.get());

    // If the client doesn't have a backend, it wasn't ever properly instantiated.
    if ( backend ) {
        backend->Terminate();

        // Raise Cluster::websocket_client_lost() after the backend has terminated.
        // In case any messages/events were still pending, Cluster::websocket_client_lost()
        // should be the last event related to this WebSocket client.
        auto rec =
            zeek::cluster::detail::bif::make_endpoint_info(backend->NodeId(), wsc->getRemoteIp(), wsc->getRemotePort(),
                                                           TRANSPORT_TCP, it->second.application_name);
        zeek::event_mgr.Enqueue(Cluster::websocket_client_lost, std::move(rec), zeek::val_mgr->Count(close.code),
                                zeek::make_intrusive<zeek::StringVal>(close.reason));
    }

    clients.erase(it);
}

// SubscribeFinished is produced internally.
void WebSocketEventDispatcher::Process(const WebSocketSubscribeFinished& fin) {
    const auto& it = clients.find(fin.id);
    if ( it == clients.end() ) {
        reporter->Error("Subscribe finished from non-existing WebSocket client with id %s!", fin.id.c_str());
        return;
    }

    auto& entry = it->second;

    entry.wsc->SetSubscriptionActive(fin.topic_prefix);

    if ( ! entry.wsc->AllSubscriptionsActive() ) {
        // More subscriptions to come.
        return;
    }

    if ( ! entry.ready_to_publish ) {
        // Still waiting for the backend to be ready.
        return;
    }

    HandleSubscriptionsActive(entry);
}

void WebSocketEventDispatcher::Process(const WebSocketBackendReadyToPublish& ready) {
    const auto& it = clients.find(ready.id);
    if ( it == clients.end() ) {
        reporter->Error("Backend ready from non-existing WebSocket client with id %s!", ready.id.c_str());
        return;
    }

    auto& entry = it->second;

    entry.ready_to_publish = true;

    if ( ! entry.wsc->AllSubscriptionsActive() ) {
        // More subscriptions to come!
        return;
    }

    HandleSubscriptionsActive(entry);
}

void WebSocketEventDispatcher::HandleSubscriptions(WebSocketClientEntry& entry, std::string_view buf) {
    rapidjson::Document doc;
    doc.Parse(buf.data(), buf.size());
    if ( ! doc.IsArray() ) {
        entry.wsc->SendError(broker::enum_str(broker::ec::deserialization_failed), "subscriptions not an array");
        return;
    }

    std::vector<std::string> subscriptions;

    for ( rapidjson::SizeType i = 0; i < doc.Size(); i++ ) {
        if ( ! doc[i].IsString() ) {
            entry.wsc->SendError(broker::enum_str(broker::ec::deserialization_failed),
                                 "individual subscription not a string");
            return;
        }

        subscriptions.emplace_back(doc[i].GetString());
    }

    entry.wsc->SetSubscriptions(subscriptions);

    auto cb = [this, id = entry.id, wsc = entry.wsc](const std::string& topic,
                                                     const Backend::SubscriptionCallbackInfo& info) {
        if ( info.status == Backend::CallbackStatus::Error ) {
            zeek::reporter->Error("Subscribe for WebSocket client failed!");

            // Is this going to work out?
            QueueReply(WebSocketCloseReply{wsc, 1011, "Could not subscribe. Something bad happened!"});
        }
        else {
            Process(WebSocketSubscribeFinished{id, topic});
        }
    };

    for ( const auto& subscription : subscriptions ) {
        if ( ! entry.backend->Subscribe(subscription, cb) ) {
            zeek::reporter->Error("Subscribe for WebSocket client failed!");
            QueueReply(WebSocketCloseReply{entry.wsc, 1011, "Could not subscribe. Something bad happened!"});
        }
    }

    // Register a callback to be invoked when the backend is ready for publishing.
    entry.backend->ReadyToPublishCallback([this, id = entry.id](const auto& info) {
        // Ready callbacks are supposed to  run on the main thread,
        // so we can just start processing a WebSocketBackendReady.
        Process(WebSocketBackendReadyToPublish{id});
    });
}

void WebSocketEventDispatcher::HandleSubscriptionsActive(const WebSocketClientEntry& entry) {
    auto& wsc = entry.wsc;

    auto rec =
        zeek::cluster::detail::bif::make_endpoint_info(entry.backend->NodeId(), wsc->getRemoteIp(),
                                                       wsc->getRemotePort(), TRANSPORT_TCP, entry.application_name);
    auto subscriptions_vec = zeek::cluster::detail::bif::make_string_vec(wsc->GetSubscriptions());
    zeek::event_mgr.Enqueue(Cluster::websocket_client_added, std::move(rec), std::move(subscriptions_vec));

    entry.wsc->SendAck(entry.backend->NodeId(), zeek::zeek_version());

    WS_DEBUG("Sent Ack to client %s (%s:%d) %s\n", entry.id.c_str(), wsc->getRemoteIp().c_str(), wsc->getRemotePort(),
             entry.backend->NodeId().c_str());

    // Process any queued messages now.
    for ( auto& msg : entry.queue ) {
        assert(entry.msg_count > 1);
        Process(msg);
    }
}

void WebSocketEventDispatcher::HandleEvent(WebSocketClientEntry& entry, std::string_view buf) {
    // Unserialize the message as an event.
    broker::variant res;
    auto err = broker::format::json::v1::decode(buf, res);
    if ( err ) {
        entry.wsc->SendError(broker::enum_str(broker::ec::deserialization_failed), "failed to decode JSON object");
        return;
    }

    std::string topic = std::string(res->shared_envelope()->topic());

    if ( topic == broker::topic::reserved ) {
        entry.wsc->SendError(broker::enum_str(broker::ec::deserialization_failed), "no topic in top-level JSON object");
        return;
    }

    broker::zeek::Event broker_ev(std::move(res));

    // This is not guaranteed to work! If the node running the WebSocket
    // API does not have the declaration of the event that another node
    // is sending, it cannot instantiate the zeek::cluster::Event for
    // re-publishing to a cluster backend.
    //
    // Does that make conceptional sense? Basically the WebSocket API
    // has Zeek-script awareness.
    //
    // It works with Broker today because Broker treats messages opaquely.
    // It knows how to convert from JSON into Broker binary format as these
    // are compatible.
    //
    // However, the broker format is under specified (vectors are used for various
    // types without being tagged explicitly), so it's not possible to determine
    // the final Zeek type without having access to the script-layer.
    //
    // I'm not sure this is a real problem, other than it being unfortunate that
    // the Zeek process running the WebSocket API requires access to all declarations
    // of events being transmitted via WebSockets. Though this might be a given anyhow.
    //
    // See broker/Data.cc for broker::vector conversion to see the collisions:
    // vector, list, func, record, pattern, opaque are all encoded using
    // broker::vector rather than dedicated types.
    //
    // Switching to a JSON v2 format that ensures all Zeek types are represented
    // explicitly would help.
    auto zeek_ev = cluster::detail::to_zeek_event(broker_ev);
    if ( ! zeek_ev ) {
        entry.wsc->SendError(broker::enum_str(broker::ec::deserialization_failed), "failed to create Zeek event");
        return;
    }

    WS_DEBUG("Publishing event %s to topic '%s'", std::string(zeek_ev->HandlerName()).c_str(), topic.c_str());
    entry.backend->PublishEvent(topic, *zeek_ev);
}

// Process a WebSocket message from a client.
//
// If it's the first message, the code is expecting a subscriptions
// array, otherwise it'll be a remote event.
void WebSocketEventDispatcher::Process(const WebSocketMessage& msg) {
    const auto& id = msg.id;

    const auto& it = clients.find(id);
    if ( it == clients.end() ) {
        reporter->Error("WebSocket message from non-existing WebSocket client %s", id.c_str());
        return;
    }

    // Client without backend wasn't accepted, just discard its message.
    if ( ! it->second.backend )
        return;

    auto& entry = it->second;
    const auto& wsc = entry.wsc;
    entry.msg_count++;

    WS_DEBUG("Message %" PRIu64 " size=%zu from client %s (%s:%d) backend=%p", entry.msg_count, msg.msg.size(),
             wsc->getId().c_str(), wsc->getRemoteIp().c_str(), wsc->getRemotePort(), entry.backend.get());

    // First message is the subscription message.
    if ( entry.msg_count == 1 ) {
        WS_DEBUG("Subscriptions from client %s: (%s:%d)", id.c_str(), wsc->getRemoteIp().c_str(), wsc->getRemotePort());
        HandleSubscriptions(entry, msg.msg);
    }
    else {
        if ( ! wsc->IsAcked() ) {
            WS_DEBUG("Client sending messages before receiving ack!");
            entry.queue.push_back(msg);
            return;
        }

        HandleEvent(entry, msg.msg);
    }
}
