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
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Manager.h"

#include "ZeroMQ-Broker.h"

namespace zeek {

namespace plugin {

namespace Zeek_Cluster_Backend_ZeroMQ {

extern Plugin plugin;

} // namespace Zeek_Cluster_Backend_ZeroMQ
} // namespace plugin

namespace cluster::zeromq {

#define ZEROMQ_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Cluster_Backend_ZeroMQ::plugin, __VA_ARGS__)

#define ZEROMQ_THREAD_PRINTF(...) std::fprintf(stderr, "[zeromq] " __VA_ARGS__);

namespace {
void self_thread_fun(void* arg) {
    auto* self = static_cast<ZeroMQBackend*>(arg);
    self->Run();
}

} // namespace

void ZeroMQBackend::DoInitPostScript() {
    my_node_id = zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::my_node_id")->ToStdString();
    listen_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xpub_endpoint")->ToStdString();
    listen_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_xsub_endpoint")->ToStdString();
    connect_xpub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xpub_endpoint")->ToStdString();
    connect_xsub_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::connect_xsub_endpoint")->ToStdString();

    listen_log_endpoint =
        zeek::id::find_val<zeek::StringVal>("Cluster::Backend::ZeroMQ::listen_log_endpoint")->ToStdString();

    const auto& log_endpoints = zeek::id::find_val<zeek::VectorVal>("Cluster::Backend::ZeroMQ::connect_log_endpoints");
    for ( unsigned int i = 0; i < log_endpoints->Size(); i++ )
        connect_log_endpoints.push_back(log_endpoints->StringValAt(i)->ToStdString());

    event_unsubscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::unsubscription");
    event_subscription = zeek::event_registry->Register("Cluster::Backend::ZeroMQ::subscription");

    RegisterIOSource(IOSourceCount::DONT_COUNT);
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

    ZEROMQ_DEBUG("Closing ctx");
    ctx.close();

    // If running the broker thread, terminate it, too.
    if ( broker_thread )
        broker_thread->Shutdown();

    ZEROMQ_DEBUG("Terminated");
}

bool ZeroMQBackend::Connect() {
    ZEROMQ_DEBUG("Connect");

    auto linger_ms = static_cast<int>(zeek::id::find_val<zeek::IntVal>("Cluster::Backend::ZeroMQ::linger_ms")->AsInt());
    int xpub_nodrop = zeek::id::find_val<zeek::BoolVal>("Cluster::Backend::ZeroMQ::xpub_nodrop")->AsBool() ? 1 : 0;

    try {
        xsub = zmq::socket_t(ctx, zmq::socket_type::xsub);

        xpub = zmq::socket_t(ctx, zmq::socket_type::xpub);
        xpub.set(zmq::sockopt::linger, linger_ms);
        xpub.set(zmq::sockopt::xpub_nodrop, xpub_nodrop);

        xsub.connect(connect_xsub_endpoint);
        xpub.connect(connect_xpub_endpoint);

    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to connect ZeroMQ: %s", err.what());
    }


    log_push = zmq::socket_t(ctx, zmq::socket_type::push);
    log_pull = zmq::socket_t(ctx, zmq::socket_type::pull);

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


    for ( const auto& endp : connect_log_endpoints ) {
        ZEROMQ_DEBUG("Connecting log_push socket with %s", endp.c_str());
        log_push.connect(endp);
    }

    if ( ! listen_log_endpoint.empty() ) {
        ZEROMQ_DEBUG("Listening on log pull socket: %s", listen_log_endpoint.c_str());
        log_pull.bind(listen_log_endpoint);
    }

    // We may not be connected yet, but there's no logging either unless
    // we hook into zmq_socket_monitor.
    //
    // Check the following if we wanted to add ZeroMQ into the IO loop without
    // the flare. Maybe?
    //
    // https://funcptr.net/2012/09/10/zeromq---edge-triggered-notification/
    self_thread = std::thread(self_thread_fun, this);

    // After connecting, re-register as counting IO source so the IO loop stays alive.
    RegisterIOSource(IOSourceCount::COUNT);

    return true;
}


bool ZeroMQBackend::SpawnBrokerThread() {
    broker_thread = std::make_unique<BrokerThread>(listen_xpub_endpoint, listen_xsub_endpoint);
    return broker_thread->Start();
}


bool ZeroMQBackend::DoPublishEvent(const std::string& topic, const std::string& format,
                                   const cluster::detail::byte_buffer& buf) {
    // XXX: xpub is polled from the background thread. Not sure it's safe to publish
    // while we're polling it in parallel :-/
    //
    // We could instead use a pair or inproc socket to forward the Publish() to the
    // background thread which would then do the actual publishing.
    //
    // Or could attempt to remove the background thread and integrate with the IO loop.
    //
    // So far, there haven't been crashes though...

    // Parts to send for an event publish.
    std::array<zmq::const_buffer, 4> parts = {
        zmq::const_buffer(topic.data(), topic.size()),
        zmq::const_buffer(my_node_id.data(), my_node_id.size()),
        zmq::const_buffer(format.data(), format.size()),
        zmq::const_buffer(buf.data(), buf.size()),
    };

    for ( size_t i = 0; i < parts.size(); i++ ) {
        zmq::send_flags flags = zmq::send_flags::dontwait;
        if ( i < parts.size() - 1 )
            flags = flags | zmq::send_flags::sndmore;

        zmq::send_result_t result;
        do {
            try {
                result = xpub.send(parts[i], flags);
            } catch ( zmq::error_t& err ) {
                // XXX: Not sure if the return false is so great here.
                //
                // Also, if we fail to publish, should we block rather
                // than discard?
                zeek::reporter->Error("Failed to publish to %s: %s (%d)", topic.c_str(), err.what(), err.num());
                return false;
            }
            // EAGAIN returns empty result, means try again!
        } while ( ! result );
    }

    return true;
}

bool ZeroMQBackend::DoSubscribe(const std::string& topic_prefix) {
    ZEROMQ_DEBUG("Subscribing to %s", topic_prefix.c_str());
    try {
        std::string msg = "\x01" + topic_prefix;
        xsub.send(zmq::const_buffer(msg.data(), msg.size()));
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to subscribe to topic %s: %s", topic_prefix.c_str(), err.what());
        return false;
    }

    return true;
}

bool ZeroMQBackend::DoUnsubscribe(const std::string& topic_prefix) {
    ZEROMQ_DEBUG("Unsubscribing %s", topic_prefix.c_str());
    try {
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
    static std::string message_type = "log-write";

    log_push.send(zmq::const_buffer{my_node_id.data(), my_node_id.size()},
                  zmq::send_flags::sndmore | zmq::send_flags::dontwait);

    log_push.send(zmq::const_buffer{format.data(), format.size()},
                  zmq::send_flags::sndmore | zmq::send_flags::dontwait);
    log_push.send(zmq::const_buffer{message_type.data(), message_type.size()},
                  zmq::send_flags::sndmore | zmq::send_flags::dontwait);

    zmq::send_result_t result;
    result = log_push.send(zmq::const_buffer{buf.data(), buf.size()}, zmq::send_flags::dontwait);

    if ( ! result ) {
        // XXX: It's not exactly clear what we should do if we reach HWM.
        //      we could block and hope a logger comes along that empties
        //      our internal queue, or discard messages and log very loudly
        //      and have metrics. This may happen regularly at shutdown.
        //
        //      Maybe that should be configurable?
        reporter->Error("Failed to send log write HWM reached?!");
        return false;
    }

    return true;
}

using MultipartMessage = std::vector<zmq::message_t>;

void ZeroMQBackend::Run() {
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
            qmsgs.emplace_back(LogMessage{.format = std::string(msg[1].data<const char>(), msg[1].size()),
                                          .payload = std::move(payload)});
        }

        QueueForProcessing(std::move(qmsgs));
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
                auto* end = msg[0].data<std::byte>() + msg.size();
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
            if ( sender == my_node_id )
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
        std::function<void(const std::vector<MultipartMessage>&)> handler;
    };

    std::vector<SocketInfo> sockets = {{.socket = xsub, .name = "xsub", .handler = HandleXSubMessages},
                                       {.socket = xpub, .name = "xpub", .handler = HandleXPubMessages},
                                       {.socket = log_pull, .name = "log_pull", .handler = HandleLogMessages}};

    std::vector<zmq::pollitem_t> poll_items(sockets.size());

    while ( true ) {
        for ( size_t i = 0; i < sockets.size(); i++ )
            poll_items[i] = {.socket = sockets[i].socket.handle(), .fd = 0, .events = ZMQ_POLLIN | ZMQ_POLLERR};

        // Awkward.
        std::array<std::vector<std::vector<zmq::message_t>>, 3> rcv_messages = {};
        try {
            int r = zmq::poll(poll_items, std::chrono::seconds(-1));

            for ( size_t i = 0; i < poll_items.size(); i++ ) {
                const auto& item = poll_items[i];

                // ZEROMQ_THREAD_PRINTF("poll: items[%lu]=%s %s %s\n", i, sockets[i].name.c_str(),
                //                      item.revents & ZMQ_POLLIN ? "pollin " : "",
                //                      item.revents & ZMQ_POLLERR ? "err" : "");

                if ( item.revents & ZMQ_POLLERR ) {
                    // What should we be doing? Re-open sockets? Terminate?
                    ZEROMQ_THREAD_PRINTF("poll: error: POLLERR on socket %zu %s %p revents=%x\n", i,
                                         sockets[i].name.c_str(), item.socket, item.revents);
                }

                // Nothing to do?
                if ( (item.revents & ZMQ_POLLIN) == 0 )
                    continue;

                bool consumed_one = false;

                // Read as many messages as possible.
                do {
                    zmq::message_t msg;
                    rcv_messages[i].emplace_back(); // make room for a multiparte message

                    auto& into = rcv_messages[i].back();

                    consumed_one = false;
                    bool more = false;

                    // Read a multi-part message.
                    do {
                        auto r = sockets[i].socket.recv(msg, zmq::recv_flags::dontwait);
                        if ( r ) {
                            consumed_one = true;
                            more = msg.more();
                            into.emplace_back(std::move(msg));
                        }
                        else {
                            // EAGAIN and more flag set? Try again, otherwise.
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

        zeek::EventHandlerPtr eh = tag == 1 ? event_subscription : event_unsubscription;
        zeek::event_mgr.Enqueue(eh, zeek::make_intrusive<zeek::StringVal>(topic));
        return true;
    }
    else {
        zeek::reporter->Error("Ignoring bad BackendMessage tag=%d", tag);
        return false;
    }
}


} // namespace cluster::zeromq
} // namespace zeek
