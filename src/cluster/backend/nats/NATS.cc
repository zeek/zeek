// See the file "COPYING" in the main distribution directory for copyright.

#include "NATS.h"

#include <nats/nats.h>
#include <memory>
#include <mutex>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Flare.h"
#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"
#include "zeek/logging/Manager.h"


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

namespace detail {

namespace {

void subscription_handler_cb(natsConnection* nc, natsSubscription* sub, natsMsg* msg, void* closure);
void subscription_error_handler_cb(natsConnection* nc, natsSubscription* sub, natsStatus err, void* closure);
void connection_closed_cb(natsConnection* nc, void* closure);
void connection_disconnected_cb(natsConnection* nc, void* closure);
void connection_reconnected_cb(natsConnection* nc, void* closure);

} // namespace

class NATSManagerImpl : public zeek::iosource::IOSource {
public:
    explicit NATSManagerImpl(EventSerializer* event_serializer, LogSerializer* log_serializer)
        : event_serializer(event_serializer), log_serializer(log_serializer) {
        publish_buffer.resize(4096);
    }

    struct SubscriptionMessage {
        natsSubscription* sub;
        natsMsg* msg;
    };

    bool Connect() {
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

        // Notify script land that the connection has been established.
        zeek::event_mgr.Enqueue(event_nats_connected, zeek::Args{});

        // Register as counting.
        zeek::iosource_mgr->Register(this, false /* counts*/, false /*manage_lifetime*/);

        return true;
    }

    bool Connected() const { return conn != nullptr; }

    /**
     * Setup options
     */
    void InitPostScript() {
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

        zeek::iosource_mgr->Register(this, true /* dont count*/, false /*manage_lifetime*/);
        if ( ! zeek::iosource_mgr->RegisterFd(message_flare.FD(), this) ) {
            zeek::reporter->Error("Failed to register message_flare with IO source");
            return;
        }

        event_nats_connected = zeek::event_registry->Register("Cluster::Backend::NATS::connected");
        event_nats_disconnected = zeek::event_registry->Register("Cluster::Backend::NATS::disconnected");
        event_nats_reconnected = zeek::event_registry->Register("Cluster::Backend::NATS::reconnected");

        // Get configuration options for subscribing from the logging queue group.
        logger_queue_consume = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::NATS::logger_queue_consume")->Get();
        logger_queue_name =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::NATS::logger_queue_name")->ToStdString();
        logger_queue_subject_prefix =
            zeek::id::find_val<zeek::StringVal>("Cluster::Backend::NATS::logger_queue_subject_prefix")->ToStdString();
    }

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
        if ( ! Connected() ) {
            // Should be a metric!
            zeek::reporter->Warning("PublishEvent: Connection failed: %s", nats_GetLastError(nullptr));
            return false;
        }

        publish_buffer.clear();

        if ( ! event_serializer->SerializeEventInto(publish_buffer, event) )
            return false;

        natsMsg* msg = nullptr;
        const char* reply = nullptr;
        natsStatus status = NATS_OK;
        if ( status = natsMsg_Create(&msg, topic.c_str(), reply, reinterpret_cast<const char*>(publish_buffer.data()),
                                     publish_buffer.size());
             status != NATS_OK ) {
            zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
            return false;
        }


        // This is only queued/copied for sending.
        if ( status = natsConnection_PublishMsg(conn, msg); status != NATS_OK ) {
            zeek::reporter->Error("Failed to natsConnection_PublishMsg: %s", nats_GetLastError(nullptr));
            natsMsg_Destroy(msg);
            return false;
        }
        natsMsg_Destroy(msg);
        msg = nullptr;

        return true;
    }

    bool TrySubscribe(const std::string& topic_prefix, natsSubscription** sub) {
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

    bool Subscribe(const std::string& topic_prefix) {
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

    bool Unsubscribe(const std::string& topic_prefix) {
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

    bool PublishLogWrite(const logging::detail::LogWriteHeader& header,
                         zeek::Span<logging::detail::LogRecord> records) {
        // TODO: Should the string version of stream_id just be part of the LogWriteHeader?
        auto stream_id_num = header.stream_id->AsEnum();
        const char* stream_id = header.stream_id->GetType()->AsEnumType()->Lookup(stream_id_num);

        if ( ! stream_id ) {
            reporter->Error("Failed to remotely log: stream %" PRId64 " doesn't have name", header.stream_id->AsEnum());
            return false;
        }

        std::string subject = logger_queue_subject_prefix + stream_id + "." + header.filter_name + "." + header.path;

        cluster::detail::byte_buffer buf;
        if ( ! log_serializer->SerializeLogWriteInto(buf, header, records) ) {
            return false;
        }

        natsMsg* msg = nullptr;
        const char* reply = nullptr;
        natsStatus status = NATS_OK;
        if ( status =
                 natsMsg_Create(&msg, subject.c_str(), reply, reinterpret_cast<const char*>(buf.data()), buf.size());
             status != NATS_OK ) {
            zeek::reporter->Error("Failed to create message: %s", nats_GetLastError(nullptr));
            return false;
        }

        NATS_DEBUG("Publishing %zu log records (%zu bytes) to subject %s", records.size(), buf.size(), subject.c_str());

        if ( status = natsConnection_PublishMsg(conn, msg); status != NATS_OK ) {
            zeek::reporter->Error("Failed natsConnection_PublishMsg in PublishLogWrite(): %s",
                                  nats_GetLastError(nullptr));
            natsMsg_Destroy(msg);
            return false;
        }

        natsMsg_Destroy(msg);
        msg = nullptr;
        return true;
    }

    void Terminate() {
        for ( auto& sub : subscriptions ) {
            if ( sub.sub )
                natsSubscription_Destroy(sub.sub);
            sub.sub = nullptr;
        }
        subscriptions.clear();

        // Should we publish a "bye" to some topic so that others know we're about
        // to go down? Could also do that from script land?
        natsConnection_Destroy(conn);

        zeek::iosource_mgr->UnregisterFd(message_flare.FD(), this);
    }

    // This is invoked by the subscriber threads, need to be somewhat
    // careful what we're doing here.
    void HandleSubscriptionMessage(natsSubscription* sub, natsMsg* msg) {
        std::scoped_lock lock(messages_mtx);
        messages.push_back({sub, msg});
        if ( messages.size() == 1 )
            message_flare.Fire();
    }

    // Warning: May be called from threads!
    void HandleSubscriptionError(natsSubscription* sub, natsStatus err) {
        std::fprintf(stderr, "NATS: Subscription error: %s\n", natsStatus_GetText(err));

        // TODO: Need to somehow recover or properly report errors.
        // Also, this may run in a thread, so need to go through messages?
    }

    enum class ConnectionEvent : int {
        Closed, // permanently lost
        Disconnected,
        Reconnected,
    };

    void HandleConnectionCallback(ConnectionEvent ev) {
        // XXX: Which thread runs this?
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

        // TODO: Do something elaborate here?
    }

    /*
     * IO source code.
     */

    /**
     * Move all messages available while holding a lock, then
     * process each message unocked.
     *
     * Think this is similar to what broker's mailbox proxy does.
     */
    void Process() override {
        std::vector<SubscriptionMessage> to_process;
        {
            std::scoped_lock lock(messages_mtx);
            message_flare.Extinguish();
            to_process = std::move(messages);
            messages.clear();
        }

        for ( const auto& sub_msg : to_process ) {
            const std::byte* payload = reinterpret_cast<const std::byte*>(natsMsg_GetData(sub_msg.msg));
            size_t payload_size = natsMsg_GetDataLength(sub_msg.msg);

            if ( sub_msg.sub == logger_queue_subscription ) {
                auto r = log_serializer->UnserializeLogWrite(payload, payload_size);
                natsMsg_Destroy(sub_msg.msg); // This is deep copy, for the better or worse
                if ( r ) {
                    zeek::log_mgr->WritesFromRemote(r->header, std::move(r->records));
                }
                else
                    zeek::reporter->Error("Failed to unserialize log record using %s", log_serializer->Name().c_str());

                continue;
            }


            // If it wasn't a log message, it's an event :-)
            auto r = event_serializer->UnserializeEvent(payload, payload_size);
            natsMsg_Destroy(sub_msg.msg); // This is deep copy, for the better or worse

            if ( ! r )
                continue;

            auto& event = *r;

            zeek::event_mgr.Enqueue(event.Handler(), std::move(event.args), util::detail::SOURCE_BROKER, 0, nullptr,
                                    event.timestamp);
        }
    }

    double GetNextTimeout() override { return -1; }

    const char* Tag() override { return "NATS"; }

private:
    std::unique_ptr<EventSerializer> event_serializer;
    std::unique_ptr<cluster::LogSerializer> log_serializer;
    cluster::detail::byte_buffer publish_buffer;

    bool logger_queue_consume = false;
    std::string logger_queue_name;
    std::string logger_queue_subject_prefix;
    natsSubscription* logger_queue_subscription = nullptr;

    natsOptions* options = nullptr;
    natsConnection* conn = nullptr;

    struct Subscription {
        std::string subject;
        natsSubscription* sub;
    };

    std::vector<Subscription> subscriptions;

    std::mutex messages_mtx;
    std::vector<SubscriptionMessage> messages;
    zeek::detail::Flare message_flare;

    EventHandlerPtr event_nats_connected;
    EventHandlerPtr event_nats_disconnected;
    EventHandlerPtr event_nats_reconnected;
};

namespace {
void subscription_handler_cb(natsConnection* nc, natsSubscription* sub, natsMsg* msg, void* closure) {
    auto* impl = static_cast<detail::NATSManagerImpl*>(closure);
    impl->HandleSubscriptionMessage(sub, msg);
}

void subscription_error_handler_cb(natsConnection* nc, natsSubscription* sub, natsStatus err, void* closure) {
    auto* impl = static_cast<detail::NATSManagerImpl*>(closure);
    impl->HandleSubscriptionError(sub, err);
}

void connection_closed_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<detail::NATSManagerImpl*>(closure);
    impl->HandleConnectionCallback(NATSManagerImpl::ConnectionEvent::Closed);
}

void connection_disconnected_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<detail::NATSManagerImpl*>(closure);
    impl->HandleConnectionCallback(NATSManagerImpl::ConnectionEvent::Disconnected);
}

void connection_reconnected_cb(natsConnection* nc, void* closure) {
    auto* impl = static_cast<detail::NATSManagerImpl*>(closure);
    impl->HandleConnectionCallback(NATSManagerImpl::ConnectionEvent::Reconnected);
}
} // namespace

} // namespace detail

NATSBackend::NATSBackend(EventSerializer* event_serializer, LogSerializer* log_serializer) {
    impl = std::make_unique<nats::detail::NATSManagerImpl>(event_serializer, log_serializer);
}
NATSBackend::~NATSBackend() {}

bool NATSBackend::Connect() { return impl->Connect(); }

void NATSBackend::InitPostScript() { impl->InitPostScript(); }

void NATSBackend::Terminate() { impl->Terminate(); }

bool NATSBackend::PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
    return impl->PublishEvent(topic, event);
}

bool NATSBackend::Subscribe(const std::string& topic_prefix) { return impl->Subscribe(topic_prefix); }

bool NATSBackend::Unsubscribe(const std::string& topic_prefix) { return impl->Unsubscribe(topic_prefix); }

bool NATSBackend::PublishLogWrites(const logging::detail::LogWriteHeader& header,
                                   zeek::Span<logging::detail::LogRecord> records) {
    return impl->PublishLogWrite(header, records);
}

} // namespace cluster::nats
} // namespace zeek
