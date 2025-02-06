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
    State(broker::endpoint& endpoint, broker::subscriber subscriber)
        : endpoint(endpoint), subscriber(std::move(subscriber)) {}

    broker::endpoint& endpoint; // XXX: This refs the broker_mgr's endpoint!
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

    state = std::make_unique<State>(endpoint, std::move(subscriber));

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
    return zeek::broker_mgr->DoPublishEvent(topic, event);
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

    BROKER_WS_DEBUG("Process() got %zu messages (%s)", messages.size(), NodeId().c_str());
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
