// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <thread>
#include <zmq.hpp>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

#include "ZeroMQ-Broker.h"

namespace zeek::cluster::zeromq {

class ZeroMQBackend : public cluster::ThreadedBackend {
public:
    using ThreadedBackend::ThreadedBackend;

    /**
     * Connect to the node running the broker thread.
     */
    bool Connect();

    /**
     * Spawns thread running zmq_proxy() or some reimplementation. Only one node in a
     * cluster should run the broker thread.
     */
    bool SpawnBrokerThread();

    /**
     * Run method for background thread.
     */
    void Run();


    /**
     * Component factory.
     */
    static Backend* Instantiate(std::unique_ptr<EventSerializer> event_serializer,
                                std::unique_ptr<LogSerializer> log_serializer) {
        return new ZeroMQBackend(std::move(event_serializer), std::move(log_serializer));
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

    const char* Tag() override { return "ZeroMQ"; }

    bool DoProcessBackendMessage(int tag, detail::byte_buffer_span payload) override;

    // Script level variables.
    std::string my_node_id;
    std::string connect_xsub_endpoint;
    std::string connect_xpub_endpoint;
    std::string listen_xsub_endpoint;
    std::string listen_xpub_endpoint;
    std::vector<std::string> connect_log_endpoints;
    std::string listen_log_endpoint;

    EventHandlerPtr event_subscription;
    EventHandlerPtr event_unsubscription;

    zmq::context_t ctx;
    zmq::socket_t xsub;
    zmq::socket_t xpub;

    // Sockets used for logging. The log_push socket connects
    // with one or more logger-like nodes. Logger nodes listen
    // on the log_pull socket.
    zmq::socket_t log_push;
    zmq::socket_t log_pull;

    std::thread self_thread;

    std::unique_ptr<BrokerThread> broker_thread;
};

} // namespace zeek::cluster::zeromq
