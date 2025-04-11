// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/broker/WebSocketShim.h"

#include <broker/configuration.hh>
#include <broker/data_envelope.hh>
#include <broker/endpoint.hh>
#include <broker/hub.hh>
#include <broker/message.hh>
#include <broker/subscriber.hh>
#include <broker/topic.hh>
#include <broker/zeek.hh>
#include <memory>

#include "zeek/Reporter.h"
#include "zeek/broker/Manager.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/iosource/Manager.h"

#define BROKER_WS_DEBUG(...)                                                                                           \
    do {                                                                                                               \
        DBG_LOG(DBG_BROKER, __VA_ARGS__);                                                                              \
    } while ( 0 )

namespace zeek::Broker {

class WebSocketState {
public:
    WebSocketState() : hub(broker_mgr->MakeHub({broker::topic::errors()})) {}
    ~WebSocketState() {
        // Let the manager know we're done with this hook.
        broker_mgr->ReleaseHub(hub);
    }

    broker::hub hub;
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
    state = std::make_unique<WebSocketState>();

    zeek::iosource_mgr->RegisterFd(state->hub.read_fd(), this);
    zeek::iosource_mgr->RegisterFd(state->hub.write_fd(), this);

    return true;
}

void WebSocketShim::DoTerminate() {
    if ( state ) {
        zeek::iosource_mgr->UnregisterFd(state->hub.read_fd(), this);
        zeek::iosource_mgr->UnregisterFd(state->hub.write_fd(), this);
        state.reset();
    }
}

bool WebSocketShim::DoPublishEvent(const std::string& topic, const zeek::cluster::detail::Event& event) {
    auto r = cluster::detail::to_broker_event(event);
    if ( ! r ) {
        ProcessError("broker_error", "Failed to convert Zeek event to Broker event");
        return false;
    }

    auto msg = broker::data_envelope::make(broker::topic(topic), r->as_data());
    state->hub.publish(topic, std::move(msg));
    return true;
}

bool WebSocketShim::DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) {
    BROKER_WS_DEBUG("DoSubscribe() topic %s", topic_prefix.c_str());

    // This is blocking. It should block only for the local endpoint rather
    // than waiting for remote nodes, so this should be fine.
    state->hub.subscribe(topic_prefix, true);

    if ( cb )
        cb(topic_prefix, {zeek::cluster::Backend::CallbackStatus::Success});

    BROKER_WS_DEBUG("DoSubscribe '%s' done", topic_prefix.c_str());
    return true;
}

bool WebSocketShim::DoUnsubscribe(const std::string& topic_prefix) {
    state->hub.unsubscribe(topic_prefix, true);
    return true;
}

void WebSocketShim::Process() {
    if ( ! state ) // May be processed after Terminate() is invoked from the IO loop.
        return;

    auto messages = state->hub.poll();

    BROKER_WS_DEBUG("Shim: Process() got %zu messages (%s)", messages.size(), NodeId().c_str());
    for ( auto& message : messages ) {
        auto&& topic = broker::get_topic(message);
        if ( broker::is_prefix(topic, broker::topic::errors_str) ) {
            std::string err_msg = broker::to_string(message);
            ProcessError("broker_error", broker::to_string(err_msg));
        }
        else if ( broker::is_prefix(topic, broker::topic::statuses_str) ) {
            // Ignore status messages for WebSocket clients
        }
        else {
            broker::zeek::visit_as_message([this, topic](auto& msg) { ProcessMessage(topic, msg); }, message);
        }
    }
}

void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Batch& batch) {
    batch.for_each([this, topic](auto& inner) { ProcessMessage(topic, inner); });
}

void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Event& ev) {
    auto r = cluster::detail::to_zeek_event(ev);
    if ( ! r ) {
        std::string msg = zeek::util::fmt("Could not process remote event on topic '%s'", std::string(topic).c_str());
        ProcessError("broker_error", msg);
        return;
    }

    ProcessEvent(topic, std::move(*r));
}
void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid) {
    zeek::reporter->Warning("ProcessMessage: Invalid on %s: %s", std::string(topic).c_str(),
                            invalid.to_string().c_str());
}

} // namespace zeek::Broker
