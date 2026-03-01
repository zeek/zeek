// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/backend/zeromq/ZeroMQ.h"

#include <zmq.h>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <zmq.hpp>

#include "zeek/DebugLogger.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/OnLoop.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/backend/zeromq/Plugin.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-Proxy.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util-types.h"
#include "zeek/util.h"

extern int signal_val;

namespace zeek {

namespace plugin::Zeek_Cluster_Backend_ZeroMQ {

extern zeek::plugin::Zeek_Cluster_Backend_ZeroMQ::Plugin plugin;

}

namespace cluster::zeromq {

enum class DebugFlag : uint8_t {
    NONE = 0,
    POLL = 1,
    THREAD = 2,
};

enum class InprocTag : uint8_t {
    XsubUpdate,
    Terminate,
};

constexpr DebugFlag operator&(uint8_t x, DebugFlag y) { return static_cast<DebugFlag>(x & static_cast<uint8_t>(y)); }

// NOLINTBEGIN(cppcoreguidelines-macro-usage)

#define ZEROMQ_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Cluster_Backend_ZeroMQ::plugin, __VA_ARGS__)

#define ZEROMQ_THREAD_PRINTF(...)                                                                                      \
    do {                                                                                                               \
        std::fprintf(stderr, "[zeromq] " __VA_ARGS__);                                                                 \
    } while ( 0 )

#define ZEROMQ_DEBUG_THREAD_PRINTF(flag, ...)                                                                          \
    do {                                                                                                               \
        if ( (debug_flags & flag) == flag ) {                                                                          \
            ZEROMQ_THREAD_PRINTF(__VA_ARGS__);                                                                         \
        }                                                                                                              \
    } while ( 0 )

// NOLINTEND(cppcoreguidelines-macro-usage)


/**
 * Enum for the values used for the opaque BackendMessage.
 */
enum class ZeroMQBackendMessageTag : uint8_t {
    Unsubscription = 0,
    Subscription = 1,
    MonitoringEvent = 2,
};

constexpr bool operator==(int x, ZeroMQBackendMessageTag tag) { return x == static_cast<int>(tag); }

ZeekProxyTelemetry::ZeekProxyTelemetry(zmq::socket_t&& arg_req) : req(std::move(arg_req)) {
    // Register telemetry metric callbacks with the manager. The callbacks run when someone
    // scrapes the Prometheus endpoint.
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_frontend_messages_received", {},
                                         "Number of messages received by the frontend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[0];
                                         });

    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_frontend_bytes_received", {},
                                         "Number of bytes received by the frontend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[1];
                                         });

    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_frontend_messages_sent", {},
                                         "Number of messages sent by the frontend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[2];
                                         });
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_frontend_bytes_sent", {},
                                         "Number of bytes sent by the frontend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[3];
                                         });
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_backend_messages_received", {},
                                         "Number of messages received by the backend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[4];
                                         });
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_backend_bytes_received", {},
                                         "Number of bytes received by the backend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[5];
                                         });
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_backend_messages_sent", {},
                                         "Number of messages sent by the backend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[6];
                                         });
    zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_proxy_backend_bytes_sent", {},
                                         "Number of bytes sent by the backend socket", "1", [this]() -> double {
                                             RefreshStatisticsIfNeeded();
                                             return proxy_stats[7];
                                         });
}

void ZeekProxyTelemetry::RefreshStatisticsIfNeeded() {
    // Closed? A bit weird, but lets cover this.
    if ( ! req )
        return;

    double now = util::current_time();
    if ( last_updated < now - 0.01 ) {
        RefreshStatistics();
        last_updated = util::current_time();
    }
}

void ZeekProxyTelemetry::RefreshStatistics() {
    static std::string cmd = "STATISTICS";
    static zmq::const_buffer buf{cmd.data(), cmd.size()};
    zmq::message_t msg;
    bool more = true;

    // I guess we'll see if can hang if someone queries at the wrong time during
    // shutdown. This code runs on the main thread, so it'd lockup the whole node
    // after it received SIGERM. It should be easily recognizable on the stack when
    // attaching via gdb or sending SIGABRT to dump a core. A reasonable process
    // supervisor will also forcefully kill the process after a certain timeout
    // after sending SIGTERM.
    //
    // The REQ/REP socket is inproc:// so it should be reliable and the zmq::proxy_steerable()
    // shouldn't just go away without req being closes, so this should all be safe.
    try {
        // Request.
        req.send(buf);

        // Read reply.
        for ( size_t i = 0; more; i++ ) {
            zmq::recv_result_t recv_result = req.recv(msg, zmq::recv_flags::none);

            if ( i < proxy_stats.size() )
                proxy_stats[i] = static_cast<double>(*msg.data<uint64_t>());
            else
                ZEROMQ_THREAD_PRINTF("ignoring out-of-bound proxy_stats i=%zu\n", i);

            more = msg.more();
        }
    } catch ( zmq::error_t& err ) {
        ZEROMQ_THREAD_PRINTF("unexpected exception refreshing proxy stats: %s %d", err.what(), err.num());
    }
}

void CurveConfig::configureClientCurveSockOpts(zmq::socket_t& sock) const {
    sock.set(zmq::sockopt::curve_serverkey, server_publickey);
    sock.set(zmq::sockopt::curve_secretkey, client_secretkey);
    sock.set(zmq::sockopt::curve_publickey, client_publickey);
}

void CurveConfig::configureServerCurveSockOpts(zmq::socket_t& sock) const {
    sock.set(zmq::sockopt::curve_server, true);
    sock.set(zmq::sockopt::curve_secretkey, server_secretkey);
}

void CurveConfig::initZap(zmq::context_t& ctx, ZapArgs& args) const {
    args.zap_rep = zmq::socket_t(ctx, zmq::socket_type::rep);

    // Prepare the allowed public key from the CurveConfig
    if ( client_publickey.size() == 40 ) {
        std::string raw_client_publickey(32, '\0');
        zmq_z85_decode(reinterpret_cast<uint8_t*>(raw_client_publickey.data()), client_publickey.c_str());
        args.allowed_publickeys.insert(raw_client_publickey);
    }
    else if ( ! client_publickey.empty() ) {
        zeek::reporter->FatalError("ZeroMQ/ZAP: client public key has unexpected size %zu", client_publickey.size());
    }
}

std::unique_ptr<Backend> ZeroMQBackend::Instantiate(std::unique_ptr<EventSerializer> es,
                                                    std::unique_ptr<LogSerializer> ls,
                                                    std::unique_ptr<detail::EventHandlingStrategy> ehs) {
    auto onloop_queue_hwm = zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::onloop_queue_hwm")->AsCount();
    return std::make_unique<ZeroMQBackend>(std::move(es), std::move(ls), std::move(ehs), onloop_queue_hwm);
}

ZeroMQBackend::ZeroMQBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                             std::unique_ptr<detail::EventHandlingStrategy> ehs, zeek_uint_t onloop_queue_hwm)
    : ThreadedBackend("ZeroMQ", std::move(es), std::move(ls), std::move(ehs),
                      new zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>(this, "ZeroMQ", onloop_queue_hwm)),
      main_inproc(zmq::socket_t(ctx, zmq::socket_type::pair)),
      child_inproc(zmq::socket_t(ctx, zmq::socket_type::pair)),
      // Counters for block and drop metrics.
      total_xpub_drops(
          zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_xpub_drops", {},
                                               "Number of published events dropped due to XPUB socket HWM.")),
      total_onloop_drops(
          zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_onloop_drops", {},
                                               "Number of received events dropped due to OnLoop queue full.")),
      total_msg_errors(
          zeek::telemetry_mgr->CounterInstance("zeek", "cluster_zeromq_msg_errors", {},
                                               "Number of events with the wrong number of message parts.")) {
    // Establish the socket connection between main thread and child thread
    // already in the constructor. This allows Subscribe() and Unsubscribe()
    // calls to be delayed until DoInit() was called.
    main_inproc.bind("inproc://inproc-bridge");
    child_inproc.connect("inproc://inproc-bridge");
}

ZeroMQBackend::~ZeroMQBackend() {
    try {
        // DoTerminate is idempotent.
        DoTerminate();
    } catch ( ... ) {
        // This should never happen.
        abort();
    }
}

void ZeroMQBackend::DoInitPostScript() {
    listen_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xpub_endpoint")->ToStdString();
    listen_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xsub_endpoint")->ToStdString();
    ipv6 = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::ipv6")->AsBool() ? 1 : 0;
    listen_xpub_nodrop =
        zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::listen_xpub_nodrop")->AsBool() ? 1 : 0;
    connect_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xpub_endpoint")->ToStdString();
    connect_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xsub_endpoint")->ToStdString();
    connect_xpub_nodrop =
        zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::connect_xpub_nodrop")->AsBool() ? 1 : 0;
    listen_log_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_log_endpoint")->ToStdString();

    linger_ms = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::linger_ms")->AsInt());
    poll_max_messages = zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::poll_max_messages")->Get();
    debug_flags = zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::debug_flags")->Get();
    internal_topic_prefix =
        zeek::id::find_const<zeek::StringVal>("Cluster::Backend::ZeroMQ::internal_topic_prefix")->ToStdString();
    proxy_io_threads =
        static_cast<int>(zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::proxy_io_threads")->Get());

    event_unsubscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::unsubscription");
    event_subscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::subscription");
    event_monitoring_event = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::monitoring_event");

    // xpub/xsub hwm configuration
    xpub_sndhwm = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::xpub_sndhwm")->AsInt());
    xpub_sndbuf = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::xpub_sndbuf")->AsInt());
    xsub_rcvhwm = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::xsub_rcvhwm")->AsInt());
    xsub_rcvbuf = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::xsub_rcvbuf")->AsInt());

    // log push/pull socket configuration
    log_immediate =
        static_cast<int>(zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::log_immediate")->AsBool());
    log_sndhwm = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_sndhwm")->AsInt());
    log_sndbuf = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_sndbuf")->AsInt());
    log_rcvhwm = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_rcvhwm")->AsInt());
    log_rcvbuf = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_rcvbuf")->AsInt());

    // CURVE variables for encrypting ZeroMQ connections.
    curve_config.client_publickey =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::curve_client_publickey")->ToStdString();
    curve_config.client_secretkey =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::curve_client_secretkey")->ToStdString();
    curve_config.server_publickey =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::curve_server_publickey")->ToStdString();
    curve_config.server_secretkey =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::curve_server_secretkey")->ToStdString();
}

void ZeroMQBackend::DoTerminate() {
    // If self_thread is running, notify it to shutdown via the inproc
    // socket, then wait for it to terminate.
    if ( self_thread.joinable() && ! self_thread_shutdown_requested ) {
        ZEROMQ_DEBUG("Sending terminate request via inproc socket");
        auto tag = InprocTag::Terminate;
        main_inproc.send(zmq::const_buffer(&tag, 1), zmq::send_flags::sndmore);
        main_inproc.send(zmq::const_buffer("", 0));
        self_thread_shutdown_requested = true;

        ZEROMQ_DEBUG("Joining self_thread");
        if ( self_thread.joinable() )
            self_thread.join();
        ZEROMQ_DEBUG("Joined self_thread");
    }

    ZEROMQ_DEBUG("Shutting down ctx");
    ctx.shutdown();

    // Close the sockets that are used from the main thread,
    // the remaining sockets except for the child_inproc one
    // were closed by self_thread during shutdown already.
    log_push.close();
    main_inproc.close();
    child_inproc.close();

    // If running the proxy thread, terminate it, too.
    if ( proxy_thread ) {
        ZEROMQ_DEBUG("Shutting down proxy thread");
        proxy_thread->Shutdown();
        proxy_thread.reset();
    }

    // The ZAP handler thread will have observed the ctx
    // shutdown and terminate itself.
    if ( zap_thread.joinable() )
        zap_thread.join();

    // Shutdown REQ socket for proxy telemetry, this
    // needs to be done after shutting down the proxy
    // thread, but before closing the main context,
    // otherwise ctx.close() below blocks.
    if ( proxy_telemetry ) {
        ZEROMQ_DEBUG("Shutting down proxy telemetry");
        proxy_telemetry->Shutdown();
    }

    ZEROMQ_DEBUG("Closing ctx");
    ctx.close();

    // ThreadedBackend::DoTerminate() cleans up the onloop instance.
    ThreadedBackend::DoTerminate();
    ZEROMQ_DEBUG("Terminated");
}

bool ZeroMQBackend::DoInit() {
    // Enable IPv6 support for all subsequently created sockets, if configured.
    ctx.set(zmq::ctxopt::ipv6, ipv6);

    xsub = zmq::socket_t(ctx, zmq::socket_type::xsub);
    xpub = zmq::socket_t(ctx, zmq::socket_type::xpub);
    log_push = zmq::socket_t(ctx, zmq::socket_type::push);
    log_pull = zmq::socket_t(ctx, zmq::socket_type::pull);

    xpub.set(zmq::sockopt::linger, linger_ms);

    // Enable XPUB_VERBOSE unconditional to enforce nodes receiving
    // notifications about any new subscriptions, even if they have
    // seen them before. This is needed to for the subscribe callback
    // functionality to work reliably.
    xpub.set(zmq::sockopt::xpub_nodrop, connect_xpub_nodrop);
    xpub.set(zmq::sockopt::xpub_verbose, 1);

    xpub.set(zmq::sockopt::sndhwm, xpub_sndhwm);
    xpub.set(zmq::sockopt::sndbuf, xpub_sndbuf);
    xsub.set(zmq::sockopt::rcvhwm, xsub_rcvhwm);
    xsub.set(zmq::sockopt::rcvbuf, xsub_rcvbuf);

    if ( curve_config.isClientEnabled() ) {
        ZEROMQ_DEBUG("Enabling encryption on client XPUB and XSUB sockets");
        curve_config.configureClientCurveSockOpts(xpub);
        curve_config.configureClientCurveSockOpts(xsub);
    }

    // Create monitoring sockets for xpub, xsub and log_push sockets. For now,
    // there'll only be three client sockets.
    constexpr int events_to_monitor = ZMQ_EVENT_ALL;

    struct SocketMonitorParam {
        zmq::socket_ref sock;
        std::string addr;
    };

    std::array<SocketMonitorParam, 3> to_monitor = {
        SocketMonitorParam{xpub, "inproc://monitor-xpub"},
        SocketMonitorParam{xsub, "inproc://monitor-xsub"},
        SocketMonitorParam{log_push, "inproc://monitor-log-push"},
    };

    assert(to_monitor.size() == monitoring_sockets.size());

    for ( size_t i = 0; i < to_monitor.size(); i++ ) {
        auto& [sock, addr] = to_monitor[i];

        ZEROMQ_DEBUG("Creating zmq_socket_monitor for %s (%p)", addr.c_str(), sock.handle());
        int r = zmq_socket_monitor(sock.handle(), addr.c_str(), events_to_monitor);
        if ( r != 0 ) {
            zeek::reporter->Error("ZeroMQ: Failed setup monitor socket for %s: %s", addr.c_str(),
                                  zmq_strerror(zmq_errno()));
            return false;
        }

        // Create and connect the other end of the PAIR socket for listening for the events.
        monitoring_sockets[i] = zmq::socket_t(ctx, zmq::socket_type::pair);
        try {
            monitoring_sockets[i].connect(addr);
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("ZeroMQ: Failed to connect monitor socket %s: %s", addr.c_str(), err.what());
            return false;
        }
    }

    try {
        xsub.connect(connect_xsub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to connect xsub socket %s: %s", connect_xsub_endpoint.c_str(),
                              err.what());
        return false;
    }

    try {
        xpub.connect(connect_xpub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to connect xpub socket %s: %s", connect_xpub_endpoint.c_str(),
                              err.what());
        return false;
    }

    ZEROMQ_DEBUG("Setting log_sndhwm=%d log_sndbuf=%d log_rcvhwm=%d log_rcvbuf=%d linger_ms=%d", log_sndhwm, log_sndbuf,
                 log_rcvhwm, log_rcvbuf, linger_ms);

    log_push.set(zmq::sockopt::sndhwm, log_sndhwm);
    log_push.set(zmq::sockopt::sndbuf, log_sndbuf);
    log_push.set(zmq::sockopt::linger, linger_ms);
    log_push.set(zmq::sockopt::immediate, log_immediate);

    if ( curve_config.isClientEnabled() ) {
        ZEROMQ_DEBUG("Enabling encryption on client log PUSH socket");
        curve_config.configureClientCurveSockOpts(log_push);
    }

    log_pull.set(zmq::sockopt::rcvhwm, log_rcvhwm);
    log_pull.set(zmq::sockopt::rcvbuf, log_rcvbuf);

    // Logger processes also become CURVE servers for the log PULL sockets
    // if encryption is enabled.
    if ( curve_config.isServerEnabled() ) {
        ZEROMQ_DEBUG("Enabling encryption on server log PULL socket");
        curve_config.configureServerCurveSockOpts(log_pull);

        // Also launch a ZAP handler thread for the log_pull socket.
        curve_config.initZap(ctx, zap_args);
        zap_thread = std::thread(zeek::cluster::zeromq::zap_thread_fun, &zap_args);
    }

    if ( ! listen_log_endpoint.empty() ) {
        ZEROMQ_DEBUG("Listening on log pull socket: %s", listen_log_endpoint.c_str());
        try {
            log_pull.bind(listen_log_endpoint);
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("ZeroMQ: Failed to bind pull socket %s: %s", listen_log_endpoint.c_str(), err.what());
            return false;
        }
    }

    // The connect_log_endpoints variable may be modified by zeek_init(), so
    // need to look it up here rather than during DoInitPostScript().
    //
    // We should've probably introduced a configuration record similar to the
    // storage framework, too. Hmm. Maybe in the future.
    const auto& log_endpoints = zeek::id::find_val<zeek::VectorVal>("Cluster::Backend::ZeroMQ::connect_log_endpoints");
    for ( unsigned int i = 0; i < log_endpoints->Size(); i++ )
        connect_log_endpoints.push_back(log_endpoints->StringValAt(i)->ToStdString());

    for ( const auto& endp : connect_log_endpoints ) {
        ZEROMQ_DEBUG("Connecting log_push socket with %s", endp.c_str());
        try {
            log_push.connect(endp);
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("ZeroMQ: Failed to connect push socket %s: %s", endp.c_str(), err.what());
            return false;
        }
    }

    // At this point we've connected xpub/xsub and any logging endpoints.
    // However, we cannot tell if we're connected to anything as ZeroMQ does
    // not trivially expose this information.
    //
    // There is the zmq_socket_monitor() API that we could use to get some
    // more low-level events in the future for logging and possibly script
    // layer eventing: http://api.zeromq.org/4-2:zmq-socket-monitor


    // As of now, message processing happens in a separate thread that is
    // started below. If we wanted to integrate ZeroMQ as a selectable IO
    // source rather than going through ThreadedBackend and its flare, the
    // following post might be useful:
    //
    // https://funcptr.net/2012/09/10/zeromq---edge-triggered-notification/

    // Thread is joined in backend->DoTerminate(), backend outlives it.
    self_thread = std::thread([](auto* backend) { backend->Run(); }, this);

    // After connecting, call ThreadedBackend::DoInit() to register
    // the IO source with the loop.
    return ThreadedBackend::DoInit();
}

bool ZeroMQBackend::SpawnZmqProxyThread() {
    // Create a inproc REQ/REP connection for use by ProxyTelmeetry so that
    // we can request statistics telemetry callbacks from the zmq::proxy_steerable()
    // invocation running in a separate thread.
    std::string control_endpoint = "inproc://proxy-control";
    zmq::socket_t req(zmq::socket_t(ctx, zmq::socket_type::req));
    zmq::socket_t rep(zmq::socket_t(ctx, zmq::socket_type::rep));

    try {
        rep.bind(control_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind proxy control socket %s: %s (%d)", control_endpoint.c_str(),
                              err.what(), err.num());
        return false;
    }

    try {
        req.connect(control_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to connect proxy control socket %s: %s (%d)", control_endpoint.c_str(),
                              err.what(), err.num());
        return false;
    }

    proxy_telemetry = std::make_unique<ZeekProxyTelemetry>(std::move(req));
    proxy_thread = std::make_unique<ProxyThread>(listen_xpub_endpoint, listen_xsub_endpoint, std::move(rep), ipv6,
                                                 listen_xpub_nodrop, proxy_io_threads, curve_config);
    return proxy_thread->Start();
}

bool ZeroMQBackend::DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) {
    // Publishing an event happens as a multipart message with 4 parts:
    //
    // * The topic to publish to - this is required by XPUB/XSUB
    // * The node's identifier - see Cluster::node_id().
    // * The format used to serialize the event.
    // * The serialized event itself.
    std::array<zmq::const_buffer, 4> parts = {
        zmq::const_buffer(topic.data(), topic.size()),
        zmq::const_buffer(NodeId().data(), NodeId().size()),
        zmq::const_buffer(format.data(), format.size()),
        zmq::const_buffer(buf.data(), buf.size()),
    };

    ZEROMQ_DEBUG("Publishing %zu bytes to %s", buf.size(), topic.c_str());

    for ( size_t i = 0; i < parts.size(); i++ ) {
        zmq::send_flags flags = zmq::send_flags::none;
        if ( i < parts.size() - 1 )
            flags = flags | zmq::send_flags::sndmore;

        // This never returns EAGAIN. A pair socket blocks whenever the hwm
        // is reached, regardless of passing any dontwait flag.
        //
        // This can result in blocking on Cluster::publish() if the inner
        // thread does not consume from child_inproc.
        try {
            main_inproc.send(parts[i], flags);
        } catch ( const zmq::error_t& err ) {
            // If send() was interrupted and Zeek caught an interrupt or term signal,
            // fail the publish as we're about to shutdown. There's nothing the user
            // can do, but it indicates an overload situation as send() was blocking.
            if ( err.num() == EINTR && (signal_val == SIGINT || signal_val == SIGTERM) ) {
                zeek::reporter->Error("Failed publish() using ZeroMQ backend at shutdown: %s (signal_val=%d)",
                                      err.what(), signal_val);
                return false;
            }

            zeek::reporter->Error("Unexpected ZeroMQ::DoPublishEvent() error: %s", err.what());
            return false;
        }
    }

    return true;
}

bool ZeroMQBackend::DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) {
    ZEROMQ_DEBUG("Subscribing to %s", topic_prefix.c_str());
    try {
        // Prepend 0x01 byte to indicate subscription to XSUB socket
        // This is the XSUB API instead of setsockopt(ZMQ_SUBSCRIBE).
        std::string msg = "\x01" + topic_prefix;

        // Send two message parts. The first part is a single byte tagging the
        // message as a XSUB update. The second part the payload for the XSUB socket.
        auto tag = InprocTag::XsubUpdate;
        main_inproc.send(zmq::const_buffer(&tag, 1), zmq::send_flags::sndmore);
        main_inproc.send(zmq::const_buffer(msg.data(), msg.size()));
    } catch ( const zmq::error_t& err ) {
        zeek::reporter->Error("Failed to subscribe to topic %s: %s", topic_prefix.c_str(), err.what());
        if ( cb )
            cb(topic_prefix, {CallbackStatus::Error, err.what()});

        return false;
    }

    // Store the callback for later.
    if ( cb )
        subscription_callbacks.insert({topic_prefix, cb});

    return true;
}

bool ZeroMQBackend::DoUnsubscribe(const std::string& topic_prefix) {
    ZEROMQ_DEBUG("Unsubscribing %s", topic_prefix.c_str());
    try {
        // Prepend 0x00 byte to indicate unsubscription to XSUB socket.
        // This is the XSUB API instead of setsockopt(ZMQ_SUBSCRIBE).
        std::string msg = '\0' + topic_prefix;

        // Send two message parts. The first part is a single byte tagging the
        // message as a XSUB update. The second part the payload for the XSUB socket.
        auto tag = InprocTag::XsubUpdate;
        main_inproc.send(zmq::const_buffer(&tag, 1), zmq::send_flags::sndmore);
        main_inproc.send(zmq::const_buffer(msg.data(), msg.size()));
    } catch ( const zmq::error_t& err ) {
        zeek::reporter->Error("Failed to unsubscribe from topic %s: %s", topic_prefix.c_str(), err.what());
        return false;
    }

    return true;
}

bool ZeroMQBackend::DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                                       byte_buffer& buf) {
    static std::string message_type = "log-write";

    // Publishing a log write is done using 4 parts
    //
    // * A constant "log-write" string
    // * The node's identifier - see Cluster::node_id().
    // * The format used to serialize the log write.
    // * The serialized log write itself.
    std::array<zmq::const_buffer, 4> parts = {
        zmq::const_buffer{message_type.data(), message_type.size()},
        zmq::const_buffer(NodeId().data(), NodeId().size()),
        zmq::const_buffer{format.data(), format.size()},
        zmq::const_buffer{buf.data(), buf.size()},
    };

    // If the log_push socket isn't yet initialized or has been closed, just return.
    if ( ! log_push ) {
        ZEROMQ_DEBUG("Skipping log write - log_push socket not open");
        return false;
    }

    ZEROMQ_DEBUG("Publishing %zu bytes of log writes (path %s)", buf.size(), header.path.c_str());

    for ( size_t i = 0; i < parts.size(); i++ ) {
        zmq::send_flags flags = zmq::send_flags::dontwait;
        if ( i < parts.size() - 1 )
            flags = flags | zmq::send_flags::sndmore;

        zmq::send_result_t result;
        try {
            result = log_push.send(parts[i], flags);
        } catch ( const zmq::error_t& err ) {
            zeek::reporter->Error("Failed to send log write part %zu: %s", i, err.what());
            return false;
        }

        if ( ! result ) {
            // XXX: Not  exactly clear what we should do if we reach HWM.
            //      we could block and hope a logger comes along that empties
            //      our internal queue, or discard messages and log very loudly
            //      and have metrics about it. However, this may happen regularly
            //      at shutdown.
            //
            //      Maybe that should be configurable?

            // If no logging endpoints were configured, that almost seems on
            // purpose (and there's a warning elsewhere about this), so skip
            // logging an error when sending fails.
            if ( connect_log_endpoints.empty() )
                return true;

            reporter->Error("Failed to send log write. HWM reached?");
            return false;
        }
    }

    return true;
}

// Forward messages from the inprocess bridge.
//
// Either it's 2 parts (tag and payload) for controlling subscriptions
// or terminating the thread, or it is 4 parts in which case all the parts
// are forwarded to the XPUB socket directly for publishing.
void ZeroMQBackend::HandleInprocMessages(std::vector<MultipartMessage>& msgs) {
    for ( auto& msg : msgs ) {
        if ( msg.size() == 2 ) {
            InprocTag tag = msg[0].data<InprocTag>()[0];
            switch ( tag ) {
                case InprocTag::XsubUpdate: {
                    xsub.send(msg[1], zmq::send_flags::none);
                    break;
                }
                case InprocTag::Terminate: {
                    if ( self_thread_stop )
                        ZEROMQ_THREAD_PRINTF("inproc: error: duplicate shutdown message");
                    self_thread_stop = true;
                }
            }
        }
        else if ( msg.size() == 4 ) {
            for ( auto& part : msg ) {
                zmq::send_flags flags = zmq::send_flags::dontwait;
                if ( part.more() )
                    flags = flags | zmq::send_flags::sndmore;

                zmq::send_result_t result;
                try {
                    result = xpub.send(part, flags);
                } catch ( zmq::error_t& err ) {
                    if ( err.num() == ETERM )
                        return;

                    // XXX: What other error can happen here? How should we react?
                    ZEROMQ_THREAD_PRINTF("xpub: Failed to publish with error %s (%d)\n", err.what(), err.num());
                    break;
                }

                // Empty result means xpub.send() returned EAGAIN. The socket reached
                // its high-water-mark and we drop this message.
                if ( ! result ) {
                    total_xpub_drops->Inc();

                    // Warn once about a dropped message.
                    //
                    // TODO: warn every n seconds?
                    if ( xpub_drop_last_warn_at == 0.0 ) {
                        ZEROMQ_THREAD_PRINTF("xpub: warn: dropped a message due to hwm\n");
                        xpub_drop_last_warn_at = util::current_time(true);
                    }

                    break; // Skip the whole message.
                }
            }
        }
        else {
            ZEROMQ_THREAD_PRINTF("inproc: error: expected 2 or 4 parts, have %zu!\n", msg.size());
            total_msg_errors->Inc();
        }
    }
}

void ZeroMQBackend::HandleLogMessages(const std::vector<MultipartMessage>& msgs) {
    for ( const auto& msg : msgs ) {
        // sender, format, type,  payload
        if ( msg.size() != 4 ) {
            ZEROMQ_THREAD_PRINTF("log: error: expected 4 parts, have %zu!\n", msg.size());
            total_msg_errors->Inc();
            continue;
        }

        byte_buffer payload{msg[3].data<std::byte>(), msg[3].data<std::byte>() + msg[3].size()};
        LogMessage lm{.format = std::string(msg[2].data<const char>(), msg[2].size()), .payload = std::move(payload)};

        // Always enqueue log messages for processing, they are important.
        //
        // Hmm, we could also consider bypassing Zeek's event loop completely and
        // just go to the log_mgr directly in the future.
        OnLoop()->QueueForProcessing(std::move(lm), zeek::detail::QueueFlag::Force);
    }
}

void ZeroMQBackend::HandleXPubMessages(const std::vector<MultipartMessage>& msgs) {
    for ( const auto& msg : msgs ) {
        if ( msg.size() != 1 ) {
            ZEROMQ_THREAD_PRINTF("xpub: error: expected 1 part, have %zu!\n", msg.size());
            total_msg_errors->Inc();
            continue;
        }

        // Check if the messages starts with \x00 or \x01 to understand if it's
        // a subscription or unsubscription message.
        auto first = *reinterpret_cast<const uint8_t*>(msg[0].data());
        if ( first == 0 || first == 1 ) {
            QueueMessage qm;
            auto* start = msg[0].data<std::byte>() + 1;
            auto* end = msg[0].data<std::byte>() + msg[0].size();
            byte_buffer topic(start, end);
            if ( first == 1 ) {
                qm = BackendMessage{static_cast<int>(ZeroMQBackendMessageTag::Subscription), std::move(topic)};
            }
            else if ( first == 0 ) {
                qm = BackendMessage{static_cast<int>(ZeroMQBackendMessageTag::Unsubscription), std::move(topic)};
            }
            else {
                ZEROMQ_THREAD_PRINTF("xpub: error: unexpected first char: have '0x%02x'", first);
                continue;
            }

            // Always enqueue subscription messages from other nodes as events.
            //
            // There shouldn't be all that many, unless some script calls Cluster::subscribe() and
            // Cluster::unsubscribe() a lot, so assume we can afford the extra memory rather than
            // missing these low-frequency events.
            OnLoop()->QueueForProcessing(std::move(qm), zeek::detail::QueueFlag::Force);
        }
    }
}

void ZeroMQBackend::HandleXSubMessages(const std::vector<MultipartMessage>& msgs) {
    for ( const auto& msg : msgs ) {
        if ( msg.size() != 4 ) {
            ZEROMQ_THREAD_PRINTF("xsub: error: expected 4 parts, have %zu!\n", msg.size());
            total_msg_errors->Inc();
            continue;
        }

        // Filter out messages that are coming from this node.
        std::string sender(msg[1].data<const char>(), msg[1].size());
        if ( sender == NodeId() )
            continue;

        byte_buffer payload{msg[3].data<std::byte>(), msg[3].data<std::byte>() + msg[3].size()};
        EventMessage em{.topic = std::string(msg[0].data<const char>(), msg[0].size()),
                        .format = std::string(msg[2].data<const char>(), msg[2].size()),
                        .payload = std::move(payload)};


        // If queueing the event message for Zeek's main loop doesn't work due to reaching the onloop hwm,
        // drop the message.
        //
        // This is sort of a suicidal snail pattern but without exiting the node.
        if ( ! OnLoop()->QueueForProcessing(std::move(em), zeek::detail::QueueFlag::DontBlock) ) {
            total_onloop_drops->Inc();

            // Warn once about a dropped message.
            if ( onloop_drop_last_warn_at == 0.0 ) {
                ZEROMQ_THREAD_PRINTF("warn: dropped a message due to onloop queue full\n");
                onloop_drop_last_warn_at = util::current_time(true);
            }
        }
    }
}

void ZeroMQBackend::HandleMonitoringMessages(const std::vector<MultipartMessage>& msgs) {
    for ( const auto& msg : msgs ) {
        if ( msg.size() == 2 ) {
            // Concatenate the frames of the monitoring event into a single string
            // and copy its content into the BackendMessage payload. The DoProcessBackendMessage()
            // implementation understands how to unpack this again.
            std::string str = msg[0].to_string() + msg[1].to_string();
            byte_buffer payload{reinterpret_cast<std::byte*>(str.data()),
                                reinterpret_cast<std::byte*>(str.data()) + str.size()};

            auto qm = BackendMessage{static_cast<int>(ZeroMQBackendMessageTag::MonitoringEvent), std::move(payload)};
            OnLoop()->QueueForProcessing(std::move(qm), zeek::detail::QueueFlag::Force);
        }
        else {
            ZEROMQ_THREAD_PRINTF("mon: error: expected 2 parts, have %zu!\n", msg.size());
            total_msg_errors->Inc();
            continue;
        }
    }
}

void ZeroMQBackend::Run() {
    char name[4 + 2 + 16 + 1]{}; // zmq-0x<8byte pointer in hex><nul>
    snprintf(name, sizeof(name), "zmq-%p", this);
    util::detail::set_thread_name(name);
    ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::THREAD, "Thread starting (%p)\n", this);

    struct SocketInfo {
        zmq::socket_ref socket;
        std::string name;
        std::function<void(std::vector<MultipartMessage>&)> handler;
    };

    std::vector<SocketInfo> sockets = {
        {.socket = child_inproc, .name = "inproc", .handler = [this](auto& msgs) { HandleInprocMessages(msgs); }},
        {.socket = xpub, .name = "xpub", .handler = [this](const auto& msgs) { HandleXPubMessages(msgs); }},
        {.socket = xsub, .name = "xsub", .handler = [this](const auto& msgs) { HandleXSubMessages(msgs); }},
        {.socket = log_pull, .name = "log_pull", .handler = [this](const auto& msgs) { HandleLogMessages(msgs); }},
        {.socket = monitoring_sockets[0],
         .name = "mon-xpub",
         .handler = [this](const auto& msgs) { HandleMonitoringMessages(msgs); }},
        {.socket = monitoring_sockets[1],
         .name = "mon-xsub",
         .handler = [this](const auto& msgs) { HandleMonitoringMessages(msgs); }},
        {.socket = monitoring_sockets[2],
         .name = "mon-log-push",
         .handler = [this](const auto& msgs) { HandleMonitoringMessages(msgs); }},
    };

    // Called when Run() terminates.
    auto deferred_close = util::Deferred([this]() {
        xpub.close();
        xsub.close();
        log_pull.close();

        for ( auto& s : monitoring_sockets )
            s.close();

        ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::THREAD, "Thread sockets closed (%p)\n", this);
    });

    std::vector<zmq::pollitem_t> poll_items(sockets.size());

    while ( ! self_thread_stop ) {
        for ( size_t i = 0; i < sockets.size(); i++ )
            poll_items[i] = {.socket = sockets[i].socket.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR};

        // Awkward.
        std::vector<std::vector<MultipartMessage>> rcv_messages(sockets.size());
        try {
            try {
                int r = zmq::poll(poll_items, std::chrono::seconds(-1));
                ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::POLL, "poll: r=%d", r);
            } catch ( const zmq::error_t& err ) {
                ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::POLL, "poll exception: what=%s num=%d", err.what(), err.num());
                // Retry interrupted zmq::poll() calls.
                if ( err.num() == EINTR )
                    continue;

                throw;
            }

            for ( size_t i = 0; i < poll_items.size(); i++ ) {
                const auto& item = poll_items[i];
                ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::POLL, "poll: items[%lu]=%s %s %s\n", i, sockets[i].name.c_str(),
                                           item.revents & ZMQ_POLLIN ? "pollin " : "",
                                           item.revents & ZMQ_POLLERR ? "err" : "");

                if ( item.revents & ZMQ_POLLERR ) {
                    // What should we be doing? Re-open sockets? Terminate?
                    ZEROMQ_THREAD_PRINTF("poll: error: POLLERR on socket %zu %s %p revents=%x\n", i,
                                         sockets[i].name.c_str(), item.socket, item.revents);
                }

                // Nothing to do?
                if ( (item.revents & ZMQ_POLLIN) == 0 )
                    continue;

                bool consumed_one = false;

                // Read messages from the socket.
                do {
                    zmq::message_t msg;
                    rcv_messages[i].emplace_back(); // make room for a multipart message
                    auto& into = rcv_messages[i].back();

                    // Only receive up to poll_max_messages from an individual
                    // socket. Move on to the next when exceeded. The last pushed
                    // message (empty) is popped at the end of the loop.
                    if ( poll_max_messages > 0 && rcv_messages[i].size() > poll_max_messages ) {
                        ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::POLL, "poll: %s rcv_messages[%zu] full!\n",
                                                   sockets[i].name.c_str(), i);
                        break;
                    }

                    consumed_one = false;
                    bool more = false;

                    // Read a multi-part message.
                    do {
                        zmq::recv_result_t recv_result;
                        try {
                            recv_result = sockets[i].socket.recv(msg, zmq::recv_flags::dontwait);
                        } catch ( const zmq::error_t& err ) {
                            // Retry interrupted recv() calls.
                            if ( err.num() == EINTR )
                                continue;

                            throw;
                        }

                        if ( recv_result ) {
                            consumed_one = true;
                            more = msg.more();
                            into.emplace_back(std::move(msg));
                        }
                        else {
                            // EAGAIN and more flag set? Try again!
                            if ( more )
                                continue;
                        }
                    } while ( more );
                } while ( consumed_one );

                assert(rcv_messages[i].back().empty());
                rcv_messages[i].pop_back();
            }
        } catch ( const zmq::error_t& err ) {
            if ( err.num() != ETERM )
                throw;

            // Shutdown.
            ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::THREAD, "Thread terminating (%p)\n", this);
            break;
        }

        // At this point, we've received anything that was readable from the sockets.
        // Now interpret and enqueue it into messages.
        for ( size_t i = 0; i < sockets.size(); i++ ) {
            if ( rcv_messages[i].empty() )
                continue;

            sockets[i].handler(rcv_messages[i]);
        }
    }
}

bool ZeroMQBackend::DoProcessBackendMessage(int tag, byte_buffer_span payload) {
    if ( tag == ZeroMQBackendMessageTag::Subscription || tag == ZeroMQBackendMessageTag::Unsubscription ) {
        std::string topic{reinterpret_cast<const char*>(payload.data()), payload.size()};
        zeek::EventHandlerPtr eh;

        if ( tag == ZeroMQBackendMessageTag::Subscription ) {
            // If this is the first time the subscription was observed, raise
            // the ZeroMQ internal event.
            if ( ! xpub_subscriptions.contains(topic) ) {
                eh = event_subscription;
                xpub_subscriptions.insert(topic);
            }

            if ( const auto& cbit = subscription_callbacks.find(topic); cbit != subscription_callbacks.end() ) {
                const auto& cb = cbit->second;
                if ( cb )
                    cb(topic, {CallbackStatus::Success, "success"});

                subscription_callbacks.erase(cbit);
            }
        }
        else if ( tag == ZeroMQBackendMessageTag::Unsubscription ) {
            eh = event_unsubscription;
            xpub_subscriptions.erase(topic);
        }

        ZEROMQ_DEBUG("BackendMessage: %s for %s", eh != nullptr ? eh->Name() : "<raising no event>", topic.c_str());
        if ( eh )
            EnqueueEvent(eh, zeek::Args{zeek::make_intrusive<zeek::StringVal>(topic)});

        return true;
    }
    else if ( tag == ZeroMQBackendMessageTag::MonitoringEvent && payload.size() >= 6 ) {
        // https://libzmq.readthedocs.io/en/latest/zmq_socket_monitor.html
        uint16_t event_number = *reinterpret_cast<const uint16_t*>(payload.data());
        uint32_t event_value = *reinterpret_cast<const uint32_t*>(payload.data() + 2);
        const char* addr_ptr = reinterpret_cast<const char*>(payload.data() + 6);
        std::string addr = {addr_ptr, payload.size() - 6};
        ZEROMQ_DEBUG("BackendMessage: monitoring_event 0x%x with value value 0x%x for socket %s", event_number,
                     event_value, addr.c_str());

        if ( event_monitoring_event )
            EnqueueEvent(event_monitoring_event, {val_mgr->Count(event_number), val_mgr->Count(event_value),
                                                  zeek::make_intrusive<zeek::StringVal>(addr)});

        return true;
    }
    else {
        zeek::reporter->Error("Ignoring bad BackendMessage with tag %d (payload size %zu)", tag, payload.size());
        return false;
    }
}

void ZeroMQBackend::DoReadyToPublishCallback(ReadyCallback cb) {
    // Setup an ephemeral subscription for a topic produced with the internal
    // topic prefix, this backend's node identifier and an incrementing counter.
    // When the SubscribeCallback for the subscription is invoked, meaning it
    // has become visible on the XPUB socket, call the provided ready callback
    // and cancel the subscription by unsubscribing from the topic again.
    //
    // The heuristic here is that seeing a subscription created by the node itself
    // also leads to the XPUB/XSUB proxy having sent all subscriptions from other
    // nodes in the cluster.
    //
    // Without this heuristic, short-lived WebSocket clients may fail to publish
    // messages as ZeroMQ implements sender-side subscription filtering and simply
    // discards messages to topics for which it hasn't seen any subscriptions yet.
    static int ready_topic_counter = 0;
    ++ready_topic_counter;

    auto scb = [this, cb = std::move(cb)](const std::string& topic_prefix, const SubscriptionCallbackInfo& sinfo) {
        Backend::ReadyCallbackInfo info{sinfo.status, sinfo.message};
        cb(info);

        // Unsubscribe again, we're not actually interested in this topic.
        Unsubscribe(topic_prefix);
    };

    std::string topic = util::fmt("%s%s.%d.", internal_topic_prefix.c_str(), NodeId().c_str(), ready_topic_counter);
    Subscribe(topic, std::move(scb));
}

} // namespace cluster::zeromq
} // namespace zeek
