// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <thread>
#include <zmq.hpp>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-Proxy.h"


namespace zeek {

namespace telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
} // namespace telemetry

namespace cluster::zeromq {

class ZeroMQBackend : public cluster::ThreadedBackend {
public:
    /**
     * Constructor.
     */
    ZeroMQBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                  std::unique_ptr<detail::EventHandlingStrategy> ehs, zeek_uint_t onloop_max_queue_size);

    /**
     * Destructor.
     */
    ~ZeroMQBackend() override;

    /**
     * Spawns a thread running zmq_proxy() for the configured XPUB/XSUB listen
     * sockets. Only one node in a cluster should do this.
     */
    bool SpawnZmqProxyThread();

    /**
     * Run method for background thread.
     */
    void Run();

    /**
     * Component factory.
     */
    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<EventSerializer> event_serializer,
                                                std::unique_ptr<LogSerializer> log_serializer,
                                                std::unique_ptr<detail::EventHandlingStrategy> ehs);

private:
    void DoInitPostScript() override;

    bool DoInit() override;

    void DoTerminate() override;

    bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) override;

    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;

    bool DoUnsubscribe(const std::string& topic_prefix) override;

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            byte_buffer& buf) override;

    bool DoProcessBackendMessage(int tag, byte_buffer_span payload) override;

    void DoReadyToPublishCallback(ReadyCallback cb) override;

    // Inner thread helper methods.
    using MultipartMessage = std::vector<zmq::message_t>;
    void HandleInprocMessages(std::vector<MultipartMessage>& msgs);
    void HandleLogMessages(const std::vector<MultipartMessage>& msgs);
    void HandleXPubMessages(const std::vector<MultipartMessage>& msgs);
    void HandleXSubMessages(const std::vector<MultipartMessage>& msgs);

    // Script level variables.
    std::string connect_xsub_endpoint;
    std::string connect_xpub_endpoint;
    std::string connect_req_endpoint;
    int connect_xpub_nodrop = 1;
    std::string listen_xsub_endpoint;
    std::string listen_xpub_endpoint;
    std::string listen_rep_endpoint;
    std::string listen_log_endpoint;
    int ipv6 = 1;
    int listen_xpub_nodrop = 1;

    int linger_ms = 0;
    zeek_uint_t poll_max_messages = 0;
    zeek_uint_t debug_flags = 0;

    std::string internal_topic_prefix;

    EventHandlerPtr event_subscription;
    EventHandlerPtr event_unsubscription;

    // xpub/xsub configuration
    int xpub_sndhwm = 1000; // libzmq default
    int xpub_sndbuf = -1;   // OS defaults
    int xsub_rcvhwm = 1000; // libzmq default
    int xsub_rcvbuf = -1;   // OS defaults

    // log socket configuration
    int log_immediate = false; // libzmq default
    int log_sndhwm = 1000;     // libzmq default
    int log_sndbuf = -1;       // OS defaults
    int log_rcvhwm = 1000;     // libzmq defaults
    int log_rcvbuf = -1;       // OS defaults

    zmq::context_t ctx;
    zmq::socket_t xsub;
    zmq::socket_t xpub;

    // inproc sockets used for sending
    // publish messages to xpub in a
    // thread safe manner.
    zmq::socket_t main_inproc;
    zmq::socket_t child_inproc;

    // Sockets used for logging. The log_push socket connects
    // with one or more logger-like nodes. Logger nodes listen
    // on the log_pull socket.
    std::vector<std::string> connect_log_endpoints;
    zmq::socket_t log_push;
    zmq::socket_t log_pull;

    std::thread self_thread;
    bool self_thread_shutdown_requested = false;
    bool self_thread_stop = false;

    int proxy_io_threads = 2;
    std::unique_ptr<ProxyThread> proxy_thread;

    // Tracking the subscriptions on the local XPUB socket.
    std::map<std::string, SubscribeCallback> subscription_callbacks;
    std::set<std::string> xpub_subscriptions;

    zeek::telemetry::CounterPtr total_xpub_drops;   // events dropped due to XPUB socket hwm reached
    zeek::telemetry::CounterPtr total_onloop_drops; // events dropped due to onloop queue full
    zeek::telemetry::CounterPtr total_msg_errors;   // messages with the wrong number of parts

    // Could rework to log-once-every X seconds if needed.
    double xpub_drop_last_warn_at = 0.0;
    double onloop_drop_last_warn_at = 0.0;
};

} // namespace cluster::zeromq
} // namespace zeek
