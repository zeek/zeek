// See the file "COPYING" in the main distribution directory for copyright.

#include "ZeroMQ.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <zmq.hpp>

#include "zeek/DebugLogger.h"
#include "zeek/EventRegistry.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/backend/zeromq/Plugin.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-Proxy.h"
#include "zeek/util.h"

namespace zeek {

namespace plugin::Zeek_Cluster_Backend_ZeroMQ {

extern zeek::plugin::Zeek_Cluster_Backend_ZeroMQ::Plugin plugin;

}

namespace cluster::zeromq {

enum class DebugFlag : zeek_uint_t {
    NONE = 0,
    POLL = 1,
};

constexpr DebugFlag operator&(zeek_uint_t x, DebugFlag y) {
    return static_cast<DebugFlag>(x & static_cast<zeek_uint_t>(y));
}

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

namespace {
void self_thread_fun(void* arg) {
    auto* self = static_cast<ZeroMQBackend*>(arg);
    self->Run();
}

} // namespace


// Constructor.
ZeroMQBackend::ZeroMQBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls)
    : ThreadedBackend(std::move(es), std::move(ls)) {
    xsub = zmq::socket_t(ctx, zmq::socket_type::xsub);
    xpub = zmq::socket_t(ctx, zmq::socket_type::xpub);
    log_push = zmq::socket_t(ctx, zmq::socket_type::push);
    log_pull = zmq::socket_t(ctx, zmq::socket_type::pull);

    main_inproc = zmq::socket_t(ctx, zmq::socket_type::pair);
    child_inproc = zmq::socket_t(ctx, zmq::socket_type::pair);
}

void ZeroMQBackend::DoInitPostScript() {
    ThreadedBackend::DoInitPostScript();

    listen_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xpub_endpoint")->ToStdString();
    listen_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xsub_endpoint")->ToStdString();
    listen_xpub_nodrop =
        zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::listen_xpub_nodrop")->AsBool() ? 1 : 0;
    connect_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xpub_endpoint")->ToStdString();
    connect_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xsub_endpoint")->ToStdString();
    listen_log_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_log_endpoint")->ToStdString();
    subscribe_busy_wait =
        zeek::id::find_val<zeek::IntervalVal>("Cluster::Backend::ZeroMQ::subscribe_busy_wait")->AsDouble();
    poll_max_messages = zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::poll_max_messages")->Get();
    debug_flags = zeek::id::find_val<zeek::CountVal>("Cluster::Backend::ZeroMQ::debug_flags")->Get();

    event_unsubscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::unsubscription");
    event_subscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::subscription");

    main_inproc.bind("inproc://publish-bridge");
    child_inproc.connect("inproc://publish-bridge");
}


void ZeroMQBackend::DoTerminate() {
    ZEROMQ_DEBUG("Shutting down ctx");
    ctx.shutdown();
    ZEROMQ_DEBUG("Joining self_thread");
    if ( self_thread.joinable() )
        self_thread.join();

    log_push.close();
    log_pull.close();
    xsub.close();
    xpub.close();
    main_inproc.close();
    child_inproc.close();

    ZEROMQ_DEBUG("Closing ctx");
    ctx.close();

    // If running the proxy thread, terminate it, too.
    if ( proxy_thread ) {
        ZEROMQ_DEBUG("Shutting down proxy thread");
        proxy_thread->Shutdown();
    }

    ZEROMQ_DEBUG("Terminated");
}

bool ZeroMQBackend::DoInit() {
    auto linger_ms = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::linger_ms")->AsInt());
    int xpub_nodrop = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::xpub_nodrop")->AsBool() ? 1 : 0;

    xpub.set(zmq::sockopt::linger, linger_ms);
    xpub.set(zmq::sockopt::xpub_nodrop, xpub_nodrop);

    try {
        xsub.connect(connect_xsub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to connect to XSUB %s: %s", connect_xsub_endpoint.c_str(), err.what());
        return false;
    }

    try {
        xpub.connect(connect_xpub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to connect to XPUB %s: %s", connect_xpub_endpoint.c_str(), err.what());
        return false;
    }


    auto log_immediate =
        static_cast<int>(zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::log_immediate")->AsBool());

    auto log_sndhwm =
        static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_sndhwm")->AsInt());

    auto log_sndbuf =
        static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_sndbuf")->AsInt());

    auto log_rcvhwm =
        static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_rcvhwm")->AsInt());

    auto log_rcvbuf =
        static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::log_rcvbuf")->AsInt());

    ZEROMQ_DEBUG("Setting log_sndhwm=%d log_sndbuf=%d log_rcvhwm=%d log_rcvbuf=%d linger_ms=%d", log_sndhwm, log_sndbuf,
                 log_rcvhwm, log_rcvbuf, linger_ms);

    log_push.set(zmq::sockopt::sndhwm, log_sndhwm);
    log_push.set(zmq::sockopt::sndbuf, log_sndbuf);
    log_push.set(zmq::sockopt::linger, linger_ms);
    log_push.set(zmq::sockopt::immediate, log_immediate);

    log_pull.set(zmq::sockopt::rcvhwm, log_rcvhwm);
    log_pull.set(zmq::sockopt::rcvbuf, log_rcvbuf);


    if ( ! listen_log_endpoint.empty() ) {
        ZEROMQ_DEBUG("Listening on log pull socket: %s", listen_log_endpoint.c_str());
        try {
            log_pull.bind(listen_log_endpoint);
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("ZeroMQ: Failed to bind to PULL socket %s: %s", listen_log_endpoint.c_str(),
                                  err.what());
            return false;
        }
    }

    const auto& log_endpoints = zeek::id::find_val<zeek::VectorVal>("Cluster::Backend::ZeroMQ::connect_log_endpoints");
    for ( unsigned int i = 0; i < log_endpoints->Size(); i++ )
        connect_log_endpoints.push_back(log_endpoints->StringValAt(i)->ToStdString());

    for ( const auto& endp : connect_log_endpoints ) {
        ZEROMQ_DEBUG("Connecting log_push socket with %s", endp.c_str());
        try {
            log_push.connect(endp);
        } catch ( zmq::error_t& err ) {
            zeek::reporter->Error("ZeroMQ: Failed to connect to PUSH socket %s: %s", endp.c_str(), err.what());
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
    self_thread = std::thread(self_thread_fun, this);

    // After connecting, call ThreadedBackend::DoInit() to register
    // the IO source with the loop.
    return ThreadedBackend::DoInit();
}

bool ZeroMQBackend::SpawnZmqProxyThread() {
    proxy_thread = std::make_unique<ProxyThread>(listen_xpub_endpoint, listen_xsub_endpoint, listen_xpub_nodrop);
    return proxy_thread->Start();
}

bool ZeroMQBackend::DoPublishEvent(const std::string& topic, const std::string& format,
                                   const cluster::detail::byte_buffer& buf) {
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

        // This should never fail, it will instead block
        // when HWM is reached. I guess we need to see if
        // and how this can happen :-/
        main_inproc.send(parts[i], flags);
    }

    return true;
}

bool ZeroMQBackend::DoSubscribe(const std::string& topic_prefix) {
    ZEROMQ_DEBUG("Subscribing to %s", topic_prefix.c_str());
    try {
        // Prepend 0x01 byte to indicate subscription to XSUB socket
        // This is the XSUB API instead of setsockopt(ZMQ_SUBSCRIBE).
        std::string msg = "\x01" + topic_prefix;
        xsub.send(zmq::const_buffer(msg.data(), msg.size()));
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to subscribe to topic %s: %s", topic_prefix.c_str(), err.what());
        return false;
    }

    if ( subscribe_busy_wait > 0.0 ) {
        double start_ts = zeek::util::current_time(true);
        Process();
        while ( xpub_subscriptions.count(topic_prefix) == 0 ) {
            if ( zeek::util::current_time() > start_ts + subscribe_busy_wait )
                break;

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            Process();
        }

        if ( xpub_subscriptions.count(topic_prefix) == 0 )
            zeek::reporter->Warning("Subscription '%s' not visible on XPUB socket after %.3f ms", topic_prefix.c_str(),
                                    subscribe_busy_wait * 1000);

        ZEROMQ_DEBUG("Subscribe to '%s' completed in %.3f ms", topic_prefix.c_str(),
                     (zeek::util::current_time() - start_ts) * 1000);
    }


    return true;
}

bool ZeroMQBackend::DoUnsubscribe(const std::string& topic_prefix) {
    ZEROMQ_DEBUG("Unsubscribing %s", topic_prefix.c_str());
    try {
        // Prepend 0x00 byte to indicate subscription to XSUB socket.
        // This is the XSUB API instead of setsockopt(ZMQ_SUBSCRIBE).
        std::string msg = "\x00" + topic_prefix;
        xsub.send(zmq::const_buffer(msg.data(), msg.size()));
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to unsubscribe from topic %s: %s", topic_prefix.c_str(), err.what());
        return false;
    }

    return true;
}

bool ZeroMQBackend::DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                                       cluster::detail::byte_buffer& buf) {
    ZEROMQ_DEBUG("Publishing %zu bytes of log writes (path %s)", buf.size(), header.path.c_str());
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

    zmq::send_result_t result;
    for ( size_t i = 0; i < parts.size(); i++ ) {
        zmq::send_flags flags = zmq::send_flags::dontwait;
        if ( i < parts.size() - 1 )
            flags = flags | zmq::send_flags::sndmore;

        result = log_push.send(parts[i], flags);
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

void ZeroMQBackend::Run() {
    using MultipartMessage = std::vector<zmq::message_t>;

    auto HandleLogMessages = [this](const std::vector<MultipartMessage>& msgs) {
        QueueMessages qmsgs;
        qmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            // sender, format, type,  payload
            if ( msg.size() != 4 ) {
                ZEROMQ_THREAD_PRINTF("log: error: expected 4 parts, have %zu!\n", msg.size());
                continue;
            }

            detail::byte_buffer payload{msg[3].data<std::byte>(), msg[3].data<std::byte>() + msg[3].size()};
            qmsgs.emplace_back(LogMessage{.format = std::string(msg[2].data<const char>(), msg[2].size()),
                                          .payload = std::move(payload)});
        }

        QueueForProcessing(std::move(qmsgs));
    };

    auto HandleInprocMessages = [this](std::vector<MultipartMessage>& msgs) {
        // Forward messages from the inprocess bridge to xpub.
        for ( auto& msg : msgs ) {
            assert(msg.size() == 4);

            for ( auto& part : msg ) {
                zmq::send_flags flags = zmq::send_flags::dontwait;
                if ( part.more() )
                    flags = flags | zmq::send_flags::sndmore;

                zmq::send_result_t result;
                do {
                    try {
                        result = xpub.send(part, flags);
                    } catch ( zmq::error_t& err ) {
                        // XXX: Not sure if the return false is so great here.
                        //
                        // Also, if we fail to publish, should we block rather
                        // than discard?
                        ZEROMQ_THREAD_PRINTF("xpub: Failed to publish: %s (%d)", err.what(), err.num());
                        break;
                    }
                    // EAGAIN returns empty result, means try again!
                } while ( ! result );
            }
        }
    };

    auto HandleXPubMessages = [this](const std::vector<MultipartMessage>& msgs) {
        QueueMessages qmsgs;
        qmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            if ( msg.size() != 1 ) {
                ZEROMQ_THREAD_PRINTF("xpub: error: expected 1 part, have %zu!\n", msg.size());
                continue;
            }

            // Check if the messages starts with \x00 or \x01 to understand if it's
            // a subscription or unsubscription message.
            auto first = *reinterpret_cast<const uint8_t*>(msg[0].data());
            if ( first == 0 || first == 1 ) {
                QueueMessage qm;
                auto* start = msg[0].data<std::byte>() + 1;
                auto* end = msg[0].data<std::byte>() + msg[0].size();
                detail::byte_buffer topic(start, end);
                if ( first == 1 ) {
                    qm = BackendMessage{1, std::move(topic)};
                }
                else if ( first == 0 ) {
                    qm = BackendMessage{0, std::move(topic)};
                }
                else {
                    ZEROMQ_THREAD_PRINTF("xpub: error: unexpected first char: have '0x%02x'", first);
                    continue;
                }

                qmsgs.emplace_back(std::move(qm));
            }
        }

        QueueForProcessing(std::move(qmsgs));
    };

    auto HandleXSubMessages = [this](const std::vector<MultipartMessage>& msgs) {
        QueueMessages qmsgs;
        qmsgs.reserve(msgs.size());

        for ( const auto& msg : msgs ) {
            if ( msg.size() != 4 ) {
                ZEROMQ_THREAD_PRINTF("xsub: error: expected 4 parts, have %zu!\n", msg.size());
                continue;
            }

            // Filter out messages that are coming from this node.
            std::string sender(msg[1].data<const char>(), msg[1].size());
            if ( sender == NodeId() )
                continue;

            detail::byte_buffer payload{msg[3].data<std::byte>(), msg[3].data<std::byte>() + msg[3].size()};
            qmsgs.emplace_back(EventMessage{.topic = std::string(msg[0].data<const char>(), msg[0].size()),
                                            .format = std::string(msg[2].data<const char>(), msg[2].size()),
                                            .payload = std::move(payload)});
        }

        QueueForProcessing(std::move(qmsgs));
    };

    struct SocketInfo {
        zmq::socket_ref socket;
        std::string name;
        std::function<void(std::vector<MultipartMessage>&)> handler;
    };

    std::vector<SocketInfo> sockets = {
        {.socket = child_inproc, .name = "inproc", .handler = HandleInprocMessages},
        {.socket = xpub, .name = "xpub", .handler = HandleXPubMessages},
        {.socket = xsub, .name = "xsub", .handler = HandleXSubMessages},
        {.socket = log_pull, .name = "log_pull", .handler = HandleLogMessages},
    };

    std::vector<zmq::pollitem_t> poll_items(sockets.size());

    while ( true ) {
        for ( size_t i = 0; i < sockets.size(); i++ )
            poll_items[i] = {.socket = sockets[i].socket.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR};

        // Awkward.
        std::vector<std::vector<MultipartMessage>> rcv_messages(sockets.size());
        try {
            int r = zmq::poll(poll_items, std::chrono::seconds(-1));
            ZEROMQ_DEBUG_THREAD_PRINTF(DebugFlag::POLL, "poll: r=%d", r);

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
                        auto recv_result = sockets[i].socket.recv(msg, zmq::recv_flags::dontwait);
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

                assert(rcv_messages[i].back().size() == 0);
                rcv_messages[i].pop_back();
            }
        } catch ( zmq::error_t& err ) {
            if ( err.num() == ETERM )
                return;

            throw;
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

bool ZeroMQBackend::DoProcessBackendMessage(int tag, detail::byte_buffer_span payload) {
    if ( tag == 0 || tag == 1 ) {
        std::string topic{reinterpret_cast<const char*>(payload.data()), payload.size()};
        zeek::EventHandlerPtr eh;

        if ( tag == 1 ) {
            eh = event_subscription;
            xpub_subscriptions.insert(topic);
        }
        else if ( tag == 0 ) {
            eh = event_unsubscription;
            xpub_subscriptions.erase(topic);
        }

        ZEROMQ_DEBUG("BackendMessage: %s for %s", eh->Name(), topic.c_str());
        return EnqueueEvent(eh, zeek::Args{zeek::make_intrusive<zeek::StringVal>(topic)});
    }
    else {
        zeek::reporter->Error("Ignoring bad BackendMessage tag=%d", tag);
        return false;
    }
}


} // namespace cluster::zeromq
} // namespace zeek
