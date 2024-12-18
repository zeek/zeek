// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/websocket/WebSocket.h"

#include <ixwebsocket/IXWebSocketServer.h>
#include <memory>

#include "zeek/DebugLogger.h"
#include "zeek/Flare.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/websocket/Plugin.h"
#include "zeek/iosource/IOSource.h"

#include "iosource/Manager.h"
#include "ixwebsocket/IXConnectionState.h"


#define WS_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Cluster_WebSocket::plugin, __VA_ARGS__)


namespace zeek::cluster::websocket {


// Process messages/events from the websocket server on the Zeek io loop.
//
// TODO: The threaded backends use this pattern, the Prometheus metrics do it, Broker manager has its own
// implementation, and Zeek's threading subsystem has its own thing, too.
//
// We should probably have this better generalized :-)
template<class Work>
class OnLoop : public zeek::iosource::IOSource {
public:
    OnLoop() { zeek::iosource_mgr->RegisterFd(flare.FD(), this); }
    void Process() override {
        std::list<Work> to_process;
        {
            std::scoped_lock lock(mtx);
            to_process.splice(to_process.end(), queue);
        }


        for ( auto& work : to_process )
            Process(std::move(work));
    }

    const char* Tag() override { return "onloop"; }

    double GetNextTimeout() override { return -1; };

    void Enqueue(Work work) {
        std::list<Work> to_queue{std::move(work)};
        bool fire = false;

        {
            std::scoped_lock lock(mtx);
            fire = queue.empty();
            queue.splice(queue.end(), to_queue);
            assert(to_queue.empty());
        }

        if ( fire )
            flare.Fire();
    }

private:
    virtual void Process(Work work) = 0;

    zeek::detail::Flare flare;
    std::mutex mtx;
    std::list<Work> queue;
};

struct WebSocketMessage {
    std::string from;
    std::string message;
};


// So, for every WebSocket client, we create a new backend?
//
// Or, should we have a single backend and do topic/subscription
// matching on top?
//
// Does this only work with "centralized" backends? What if we
// need per client specific information? I'm not sure that's needed.
class WebSocketClient {
    // ConnectionState->isTerminated() to see if the connection is gone.
    std::shared_ptr<ix::ConnectionState> connections_state;
    ix::WebSocket* webSocket;
    std::unique_ptr<zeek::cluster::Backend> backend;
};


class WebSocketDemux : public OnLoop<WebSocketMessage> {
private:
    void Process(WebSocketMessage work) override { ///
        WS_DEBUG("HOOOOORAY: %s", work.message.c_str());
    }
};

// There's a single server
std::unique_ptr<ix::WebSocketServer> server;

std::unique_ptr<WebSocketDemux> demux;


void InitPostScript() {
    // XXX

    int port = 8008;
    std::string host("127.0.0.1");
    int ping_interval_sec = 5;
    int max_connections = 100;

    WS_DEBUG("Starting server on %s:%d (ping_interval=%d)", host.c_str(), port, ping_interval_sec);

    server = std::make_unique<ix::WebSocketServer>(port, host, ix::SocketServer::kDefaultTcpBacklog, max_connections,
                                                   ix::WebSocketServer::kDefaultHandShakeTimeoutSecs,
                                                   ix::SocketServer::kDefaultAddressFamily, ping_interval_sec);

    demux = std::make_unique<WebSocketDemux>();


    server->setOnClientMessageCallback(
        [](std::shared_ptr<ix::ConnectionState> cs, ix::WebSocket& webSocket, const ix::WebSocketMessagePtr& msg) {
            if ( msg->type == ix::WebSocketMessageType::Open ) {
                WS_DEBUG("New connection from %s:%d, id=%s protocol=%s", cs->getRemoteIp().c_str(), cs->getRemotePort(),
                         cs->getId().c_str(), msg->openInfo.protocol.c_str()

                );

                // A connection state object is available, and has a default id
                // You can subclass ConnectionState and pass an alternate factory
                // to override it. It is useful if you want to store custom
                // attributes per connection (authenticated bool flag, attributes, etc...)
                // std::cout << "id: " << cs->getId() << std::endl;

                // The uri the client did connect to.
                // std::cout << "Uri: " << msg->openInfo.uri << std::endl;
                // std::cout << "Headers:" << std::endl;
                // for ( auto it : msg->openInfo.headers ) {
                // std::cout << "\t" << it.first << ": " << it.second << std::endl;
            }
            else if ( msg->type == ix::WebSocketMessageType::Message ) {
                // For an echo server, we just send back to the client whatever was received by the server
                // All connected clients are available in an std::set. See the broadcast cpp example.
                // Second parameter tells whether we are sending the message in binary or text mode.
                // Here we send it in the same mode as it was received.
                demux->Enqueue({cs->getId(), msg->str});

                webSocket.send(msg->str, msg->binary);
            }
        });


    const auto [success, reason] = server->listen();
    if ( ! success )
        zeek::reporter->FatalError("WebSocket: Unable to listen on %s:%d: %s", host.c_str(), port, reason.c_str());

    server->start();
}

void Done() { server->stop(); }
} // namespace zeek::cluster::websocket
