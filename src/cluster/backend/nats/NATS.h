// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::cluster::nats {

namespace detail {

class NATSManagerImpl;

}

class NATSBackend : public cluster::ThreadedBackend {
public:
    using ThreadedBackend::ThreadedBackend;

    /**
     * Connect to the NATS server.
     */
    bool Connect();

    void HandleSubscriptionMessage(natsSubscription* sub, natsMsg* msg);

    void HandleSubscriptionError(natsSubscription* sub, natsStatus err);

    enum class ConnectionEvent {
        Closed, // permanently lost
        Disconnected,
        Reconnected,
    };

    void HandleConnectionCallback(ConnectionEvent ev);

    static Backend* Instantiate(std::unique_ptr<EventSerializer> event_serializer,
                                std::unique_ptr<LogSerializer> log_serializer) {
        return new NATSBackend(std::move(event_serializer), std::move(log_serializer));
    }

private:
    void DoInitPostScript() override;

    void DoTerminate() override;

    bool DoPublishEvent(const std::string& topic, const std::string& format,
                        const cluster::detail::byte_buffer& buf) override;

    bool DoSubscribe(const std::string& topic_prefix) override;

    bool DoUnsubscribe(const std::string& topic_prefix) override;

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            cluster::detail::byte_buffer& buf) override;

    const char* Tag() override { return "NATS"; }

    bool Connected() const { return conn != nullptr; }

    bool TrySubscribe(const std::string& topic_prefix, natsSubscription** sub);

private:
    bool logger_queue_consume = false;
    std::string logger_queue_name;
    std::string logger_queue_subject_prefix;
    natsSubscription* logger_queue_subscription = nullptr;

    EventHandlerPtr event_nats_connected;
    EventHandlerPtr event_nats_disconnected;
    EventHandlerPtr event_nats_reconnected;

    natsOptions* options = nullptr;
    natsConnection* conn = nullptr;

    struct Subscription {
        std::string subject;
        natsSubscription* sub;
    };

    std::vector<Subscription> subscriptions;
};

} // namespace zeek::cluster::nats
