// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/broker/WebSocketShim.h"

#include <broker/configuration.hh>
#include <broker/endpoint.hh>
#include <memory>

#include "Manager.h"
#include "Reporter.h"
#include "broker/fwd.hh"
#include "broker/subscriber.hh"
#include "broker/zeek.hh"
#include "cluster/Backend.h"
#include "cluster/serializer/broker/Serializer.h"
#include "iosource/Manager.h"

#ifdef DEBUG
#define BROKER_WS_DEBUG(...)                                                                                           \
    do {                                                                                                               \
        std::fprintf(stderr, "[broker-ws-shim] " __VA_ARGS__);                                                         \
        std::fprintf(stderr, "\n");                                                                                    \
    } while ( 0 )
#else
#define BROKER_WS_DEBUG(...)                                                                                           \
    do {                                                                                                               \
    } while ( 0 )
#endif

namespace zeek::Broker {

class State {
public:
    State(broker::subscriber subscriber) : subscriber(std::move(subscriber)) {}

    broker::subscriber subscriber;
};

WebSocketShim::WebSocketShim(std::unique_ptr<zeek::cluster::EventSerializer> es,
                             std::unique_ptr<zeek::cluster::LogSerializer> ls,
                             std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs)
    : zeek::cluster::Backend(std::move(es), std::move(ls), std::move(ehs)) {}


WebSocketShim::~WebSocketShim() {
    try {
        DoTerminate();
    } catch ( ... ) {
        abort();
    }
}

bool WebSocketShim::DoInit() {
    size_t cqs = 1000;
    auto& endpoint = zeek::broker_mgr->Endpoint();

    // Create a new subscriber using broker manager's endpoint.
    //
    // @Dominik: Think this is okay to do? Anything conceptually wrong?
    auto subscriber = endpoint.make_subscriber({broker::topic::statuses(), broker::topic::errors()}, cqs);

    zeek::iosource_mgr->RegisterFd(subscriber.fd(), this);

    state = std::make_unique<State>(std::move(subscriber));

    return true;
}

void WebSocketShim::DoTerminate() {
    if ( state ) {
        zeek::iosource_mgr->UnregisterFd(state->subscriber.fd(), this);
        state->subscriber.reset();
        state.reset();
    }
}

bool WebSocketShim::DoPublishEvent(const std::string& topic, const zeek::cluster::detail::Event& event) {
    // XXX: Does this work? Does this allow other WS clients to see our own messages? No? I doubt it.

    auto r = cluster::detail::to_broker_event(event);
    if ( ! r ) {
        zeek::reporter->Warning("broker-ws-shim: Unable to convert to broker event '%s'", std::string(topic).c_str());
    }

    fprintf(stderr, "Publish directly (%s)!\n", std::string(topic).c_str());

    // For Dominik: The following publish should reach all local subscribers except
    // our own state->subscriber. How could we possibly do this?
    //
    // E.g., we want to reach other WebSocket clients as well as also subscriptions
    // of Zeek script land on zeek::broker_mgr's endpoint/subscriber.
    //
    // Would each WebSocket client need a new endpoint? Can we plumb that internally?
    zeek::broker_mgr->Endpoint().publish(topic, (*r).move_data());
    return true;
}

bool WebSocketShim::DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) {
    BROKER_WS_DEBUG("add_topic=%s", topic_prefix.c_str());
    state->subscriber.add_topic(topic_prefix, true); // XXX: block means we block the IO loop!

    if ( cb )
        cb(topic_prefix, {zeek::cluster::Backend::CallbackStatus::Success});

    return true;
}

bool WebSocketShim::DoUnsubscribe(const std::string& topic_prefix) {
    state->subscriber.remove_topic(topic_prefix, true); // XXX: block
    return true;
}

void WebSocketShim::Process() {
    auto messages = state->subscriber.poll();

    // BROKER_WS_DEBUG("Process() got %zu messages (%s)", messages.size(), NodeId().c_str());
    for ( auto& message : messages ) {
        auto&& topic = broker::get_topic(message);

        // Do we need to handle status and errors?

        broker::zeek::visit_as_message([this, topic](auto& msg) { ProcessMessage(topic, msg); }, message);
    }
}
void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Batch& batch) {
    batch.for_each([this, topic](auto& inner) { ProcessMessage(topic, inner); });
}
void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Event& ev) {
    auto r = cluster::detail::to_zeek_event(ev);
    if ( ! r ) {
        // Should we send an error to the client?
        zeek::reporter->Warning("broker-ws-shim: Could not process remote event on topic '%s'",
                                std::string(topic).c_str());
        return;
    }

    HandleRemoteEvent(topic, std::move(*r));
}
void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid) {}

} // namespace zeek::Broker
