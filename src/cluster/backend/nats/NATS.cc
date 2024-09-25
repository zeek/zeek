// See the file "COPYING" in the main distribution directory for copyright.

#include "NATS.h"

#include <nats/nats.h>
#include <nats/status.h>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/logging/Manager.h"

#include "cluster/Backend.h"


namespace zeek {

namespace plugin {

class Plugin;

namespace Zeek_Cluster_Backend_NATS {

extern plugin::Plugin plugin;

}
} // namespace plugin

#define NATS_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Cluster_Backend_NATS::plugin, __VA_ARGS__)

namespace run_state {
extern double network_time;
}

namespace cluster::nats {

namespace {

void subscription_handler_cb(natsConnection* nc, natsSubscription* sub, natsMsg* msg, void* closure) {
    auto* impl = static_cast<NATSBackend*>(closure);
    impl->HandleSubscriptionMessage(sub, msg);
}

void subscription_error_handler_cb(natsConnection* nc, natsSubscription* sub, natsStatus err, void* closure) {
    auto* impl = static_cast<NATSBackend*>(closure);
    impl->HandleSubscriptionError(sub, err);
}

void connection_closed_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<NATSBackend*>(closure);
    impl->HandleConnectionCallback(NATSBackend::ConnectionEvent::Closed);
}

void connection_disconnected_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<NATSBackend*>(closure);
    impl->HandleConnectionCallback(NATSBackend::ConnectionEvent::Disconnected);
}

void connection_reconnected_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<NATSBackend*>(closure);
    impl->HandleConnectionCallback(NATSBackend::ConnectionEvent::Reconnected);
}

} // namespace

void NATSBackend::HandleSubscriptionMessage(natsSubscription* sub, natsMsg* msg) {
    QueueMessage qm;
    auto* raw_payload = reinterpret_cast<const std::byte*>(natsMsg_GetData(msg));
    size_t payload_size = natsMsg_GetDataLength(msg);

    // Copy data for generic processing on the mainloop.
    cluster::detail::byte_buffer payload = {raw_payload, raw_payload + payload_size};

    std::string format;
    const char* raw_format = nullptr;
    if ( natsMsgHeader_Get(msg, "X-Zeek-Format", &raw_format) == NATS_OK )
        format = raw_format;

    if ( sub == logger_queue_subscription ) {
        qm = LogMessage{.format = std::move(format), .payload = std::move(payload)};
    }
    else {
        std::string subject = natsSubscription_GetSubject(sub);
        qm = EventMessage{.topic = std::move(subject), .format = std::move(format), .payload = std::move(payload)};
    }

    natsMsg_Destroy(msg);

    QueueForProcessing(QueueMessages{qm});
}
void NATSBackend::HandleSubscriptionError(natsSubscription* sub, natsStatus err) {
    // What should we do here?>
    std::fprintf(stderr, "[NATS] error: subscription error for %s (%p): %s\n", natsSubscription_GetSubject(sub), sub,
                 natsStatus_GetText(err));
}

void NATSBackend::HandleConnectionCallback(ConnectionEvent ev) {
    // XXX: Which thread runs this? Is this safe or should we go through BackendMessage?
    std::string what;
    zeek::EventHandlerPtr script_event;
    switch ( ev ) {
        case ConnectionEvent::Closed: {
            what = "closed";
            break;
        }
        case ConnectionEvent::Disconnected: {
            what = "disconnected";
            script_event = event_nats_disconnected;
            break;
        }
        case ConnectionEvent::Reconnected: {
            what = "reconnected";
            script_event = event_nats_reconnected;
            break;
        }
        default: what = "unknown?";
    }

    if ( script_event )
        zeek::event_mgr.Enqueue(script_event, zeek::Args{});

    NATS_DEBUG("connection event: %s (%d)", what.c_str(), static_cast<int>(ev));
}


void NATSBackend::DoInitPostScript() {
    natsStatus status = NATS_OK;
    if ( status = natsOptions_Create(&options); status != NATS_OK ) {
        zeek::reporter->Error("natsOption_Create failed");
        return;
    }

    const auto nats_url = zeek::id::find_val<zeek::StringVal>("Cluster::Backend::NATS::url")->ToStdString();
    if ( status = natsOptions_SetURL(options, nats_url.c_str()); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetURL failed: %s", nats_GetLastError(nullptr));
        return;
    }

    auto no_echo = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::NATS::no_echo")->AsBool();
    if ( status = natsOptions_SetNoEcho(options, no_echo); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetNoEcho failed: %s", nats_GetLastError(nullptr));
        return;
    }

    auto send_asap = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::NATS::send_asap")->AsBool();
    if ( status = natsOptions_SetSendAsap(options, send_asap); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetSendAsap failed: %s", nats_GetLastError(nullptr));
        return;
    }

    auto name = zeek::id::find_val<zeek::StringVal>("Cluster::node")->ToStdString();
    if ( status = natsOptions_SetName(options, name.c_str()); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetName failed: %s", nats_GetLastError(nullptr));
        return;
    }

    if ( status = natsOptions_SetErrorHandler(options, subscription_error_handler_cb, this); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetErrorHandler failed: %s", nats_GetLastError(nullptr));
        return;
    }

    if ( status = natsOptions_SetClosedCB(options, connection_closed_cb, this); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetClosedCB failed: %s", nats_GetLastError(nullptr));
        return;
    }

    if ( status = natsOptions_SetReconnectedCB(options, connection_reconnected_cb, this); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetReconnectedCB failed: %s", nats_GetLastError(nullptr));
        return;
    }

    if ( status = natsOptions_SetDisconnectedCB(options, connection_disconnected_cb, this); status != NATS_OK ) {
        zeek::reporter->Error("natsOptions_SetDisconnectedCB failed: %s", nats_GetLastError(nullptr));
        return;
    }

    // There's many more options, also related to user authentication
    // and SSL certificates, etc.
    event_nats_connected = zeek::event_registry->Register("Cluster::Backend::NATS::connected");
    event_nats_disconnected = zeek::event_registry->Register("Cluster::Backend::NATS::disconnected");
    event_nats_reconnected = zeek::event_registry->Register("Cluster::Backend::NATS::reconnected");

    // Get configuration options for subscribing from the logging queue group.
    logger_queue_consume = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::NATS::logger_queue_consume")->Get();
    logger_queue_name = zeek::id::find_val<zeek::StringVal>("Cluster::Backend::NATS::logger_queue_name")->ToStdString();
    logger_queue_subject_prefix =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::NATS::logger_queue_subject_prefix")->ToStdString();

    RegisterIOSource(IOSourceCount::DONT_COUNT);
}

void NATSBackend::DoTerminate() {
    NATS_DEBUG("DoTerminate!");
    for ( auto& sub : subscriptions ) {
        if ( sub.sub )
            natsSubscription_Destroy(sub.sub);
        sub.sub = nullptr;
    }
    subscriptions.clear();

    if ( logger_queue_subscription )
        natsSubscription_Destroy(logger_queue_subscription);

    natsConnection_Destroy(conn);
}

bool NATSBackend::Connect() {
    if ( conn != nullptr ) {
        zeek::reporter->Error("Connect(url) called twice?");
        return false;
    }

    natsStatus status = NATS_OK;
    if ( status = natsConnection_Connect(&conn, options); status != NATS_OK ) {
        zeek::reporter->Error("natsConnection_Connect failed: %s", nats_GetLastError(nullptr));
        return false;
    }

    // This is the first time we connected with NATS, establish any pending
    // subscriptions now.
    for ( const auto& subscription : subscriptions ) {
        natsSubscription* sub = nullptr;
        if ( ! TrySubscribe(subscription.subject, &sub) ) {
            // Not sure what to do here, seems almost fatal can there's not
            // a great way to report it back.
            zeek::reporter->Error("Pending subscription failed in Connect(): '%s' %s", subscription.subject.c_str(),
                                  nats_GetLastError(nullptr));
        }
    }

    // If configured, wild-card subscribe to the logger_queue_subject_prefix.
    if ( logger_queue_consume ) {
        auto subject = logger_queue_subject_prefix + ">";
        NATS_DEBUG("Subscribing to logger queue '%s' subject='%s'", logger_queue_name.c_str(), subject.c_str());
        if ( status = natsConnection_QueueSubscribe(&logger_queue_subscription, conn, subject.c_str(),
                                                    logger_queue_name.c_str(), subscription_handler_cb, this);
             status != NATS_OK ) {
            zeek::reporter->Error("Failed to subscribe to logger queue: '%s' %s", subject.c_str(),
                                  nats_GetLastError(nullptr));
        }
    }

    RegisterIOSource(IOSourceCount::COUNT);

    // Notify script land that the connection has been established.
    zeek::event_mgr.Enqueue(event_nats_connected, zeek::Args{});

    return true;
}


bool NATSBackend::DoPublishEvent(const std::string& topic, const std::string& format,
                                 const cluster::detail::byte_buffer& buf) {
    if ( ! Connected() ) {
        // Should be a metric!
        zeek::reporter->Warning("PublishEvent: Connection failed: %s", nats_GetLastError(nullptr));
        return false;
    }

    natsMsg* msg = nullptr;
    const char* reply = nullptr;
    natsStatus status = NATS_OK;
    if ( status = natsMsg_Create(&msg, topic.c_str(), reply, reinterpret_cast<const char*>(buf.data()), buf.size());
         status != NATS_OK ) {
        zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
        return false;
    }

    if ( status = natsMsgHeader_Set(msg, "X-Zeek-Format", format.c_str()); status != NATS_OK ) {
        zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
        natsMsg_Destroy(msg);
        return false;
    }


    // This is only queued/copied for sending.
    if ( status = natsConnection_PublishMsg(conn, msg); status != NATS_OK )
        zeek::reporter->Error("Failed to natsConnection_PublishMsg: %s", nats_GetLastError(nullptr));

    natsMsg_Destroy(msg);
    msg = nullptr;

    return status == NATS_OK;
}

bool NATSBackend::DoSubscribe(const std::string& topic_prefix) {
    if ( ! Connected() ) {
        subscriptions.push_back({topic_prefix, nullptr});
        return false;
    }

    // Ignore duplicate subscribe calls.
    for ( const auto& subscription : subscriptions )
        if ( subscription.subject == topic_prefix )
            return true;

    natsSubscription* sub;
    if ( ! TrySubscribe(topic_prefix, &sub) ) {
        // Unclear what to do. Just return false for now.
        return false;
    }

    subscriptions.push_back({topic_prefix, sub});

    NATS_DEBUG("subscribed to '%s'", topic_prefix.c_str());

    return true;
}

bool NATSBackend::DoUnsubscribe(const std::string& topic_prefix) {
    auto to_remove = subscriptions.end();
    for ( auto it = subscriptions.begin(); it != subscriptions.end(); ++it ) {
        if ( it->subject == topic_prefix )
            to_remove = it;
    }

    if ( to_remove == subscriptions.end() )
        return false;

    if ( to_remove->sub != nullptr )
        natsSubscription_Destroy(to_remove->sub);

    subscriptions.erase(to_remove);
    return true;
}

bool NATSBackend::DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                                     cluster::detail::byte_buffer& buf) {
    // TODO: Should the string version of stream_id just be part of the LogWriteHeader?
    auto stream_id_num = header.stream_id->AsEnum();
    const char* stream_id = header.stream_id->GetType()->AsEnumType()->Lookup(stream_id_num);

    if ( ! stream_id ) {
        reporter->Error("Failed to remotely log: stream %" PRId64 " doesn't have name", header.stream_id->AsEnum());
        return false;
    }

    std::string subject = logger_queue_subject_prefix + stream_id + "." + header.filter_name + "." + header.path;

    natsMsg* msg = nullptr;
    const char* reply = nullptr;
    natsStatus status = NATS_OK;
    if ( status = natsMsg_Create(&msg, subject.c_str(), reply, reinterpret_cast<const char*>(buf.data()), buf.size());
         status != NATS_OK ) {
        zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
        return false;
    }

    if ( status = natsMsgHeader_Set(msg, "X-Zeek-Format", format.c_str()); status != NATS_OK ) {
        zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
        natsMsg_Destroy(msg);
        return false;
    }

    NATS_DEBUG("Publishing log records (%zu bytes) to subject %s", buf.size(), subject.c_str());

    if ( status = natsConnection_PublishMsg(conn, msg); status != NATS_OK ) {
        zeek::reporter->Error("Failed natsConnection_PublishMsg in PublishLogWrite(): %s", nats_GetLastError(nullptr));
        natsMsg_Destroy(msg);
        return false;
    }

    natsMsg_Destroy(msg);
    msg = nullptr;
    return true;
}

bool NATSBackend::TrySubscribe(const std::string& topic_prefix, natsSubscription** sub) {
    natsStatus status = NATS_OK;
    if ( status = natsConnection_Subscribe(sub, conn, topic_prefix.c_str(), subscription_handler_cb, this);
         status != NATS_OK ) {
        zeek::reporter->Error("Subscription for %s failed: %s", topic_prefix.c_str(), nats_GetLastError(nullptr));
        return false;
    }

    // Flush the connection to ensure after Subscribe() script land can publish
    // a message and ensure this subscription is actually active on the server.
    // Probably guaranteed through FIFO semantics anyhow.
    if ( status = natsConnection_Flush(conn); status != NATS_OK ) {
        zeek::reporter->Error("natsConnection_Flush error after subscribing to '%s': %s", topic_prefix.c_str(),
                              nats_GetLastError(nullptr));
        // This is pretty bad, we should probably Disconnect() and re-establish
        // subscriptions from scratch. or some such.
        return false;
    }

    return true;
}

} // namespace cluster::nats
} // namespace zeek
