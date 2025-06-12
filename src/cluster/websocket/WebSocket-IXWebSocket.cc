// See the file "COPYING" in the main distribution directory for copyright.

// Implementation of a WebSocket server and clients using the IXWebSocket client library.
#include "zeek/cluster/websocket/WebSocket.h"

#include <sys/socket.h>
#include <memory>
#include <stdexcept>

#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/net_util.h"

#include "ixwebsocket/IXConnectionState.h"
#include "ixwebsocket/IXSocketTLSOptions.h"
#include "ixwebsocket/IXWebSocket.h"
#include "ixwebsocket/IXWebSocketSendData.h"
#include "ixwebsocket/IXWebSocketServer.h"

namespace zeek::cluster::websocket::detail::ixwebsocket {

/**
 * Implementation of WebSocketClient for the IXWebsocket library.
 */
class IxWebSocketClient : public WebSocketClient {
public:
    IxWebSocketClient(std::shared_ptr<ix::ConnectionState> cs, std::shared_ptr<ix::WebSocket> ws)
        : cs(std::move(cs)), ws(std::move(ws)) {
        if ( ! this->cs || ! this->ws )
            throw std::invalid_argument("expected ws and cs to be set");
    }

    bool IsTerminated() const override {
        if ( cs->isTerminated() )
            return true;

        auto rs = ws->getReadyState();
        return rs == ix::ReadyState::Closing || rs == ix::ReadyState::Closed;
    }

    void Close(uint16_t code, const std::string& reason) override { ws->close(code, reason); }

    SendInfo SendText(std::string_view sv) override {
        if ( cs->isTerminated() )
            return {true}; // small lie

        auto send_info = ws->sendUtf8Text(ix::IXWebSocketSendData{sv.data(), sv.size()});
        return SendInfo{send_info.success};
    }

    const std::string& getId() override { return cs->getId(); }
    const std::string& getRemoteIp() override { return cs->getRemoteIp(); }
    int getRemotePort() override { return cs->getRemotePort(); }

private:
    std::shared_ptr<ix::ConnectionState> cs;
    std::shared_ptr<ix::WebSocket> ws;
};

/**
 * Implementation of WebSocketServer using the IXWebsocket library.
 */
class IXWebSocketServer : public WebSocketServer {
public:
    IXWebSocketServer(std::unique_ptr<WebSocketEventDispatcher> dispatcher, std::unique_ptr<ix::WebSocketServer> server)
        : WebSocketServer(std::move(dispatcher)), server(std::move(server)) {}

private:
    void DoTerminate() override {
        // Stop the server.
        server->stop();
    }

    std::unique_ptr<ix::WebSocketServer> server;
};

std::unique_ptr<WebSocketServer> StartServer(std::unique_ptr<WebSocketEventDispatcher> dispatcher,
                                             const ServerOptions& options) {
    if ( ! zeek::IPAddr::IsValid(options.host.c_str()) ) {
        zeek::reporter->Error("WebSocket: Host is not a valid IP %s", options.host.c_str());
        return nullptr;
    }

    zeek::IPAddr host_addr(options.host);
    int address_family = host_addr.GetFamily() == IPv4 ? AF_INET : AF_INET6;

    auto server = std::make_unique<ix::WebSocketServer>(options.port, options.host,
                                                        ix::SocketServer::kDefaultTcpBacklog, options.max_connections,
                                                        ix::WebSocketServer::kDefaultHandShakeTimeoutSecs,
                                                        address_family, options.ping_interval_seconds);

    if ( ! options.per_message_deflate )
        server->disablePerMessageDeflate();

    const auto& tls_options = options.tls_options;
    if ( tls_options.TlsEnabled() ) {
        ix::SocketTLSOptions ix_tls_options{};
        ix_tls_options.tls = true;
        ix_tls_options.certFile = tls_options.cert_file.value();
        ix_tls_options.keyFile = tls_options.key_file.value();

        if ( tls_options.enable_peer_verification ) {
            if ( ! tls_options.ca_file.empty() )
                ix_tls_options.caFile = tls_options.ca_file;
        }
        else {
            // This is the IXWebSocket library's way of
            // disabling peer verification.
            ix_tls_options.caFile = "NONE";
        }

        if ( ! tls_options.ciphers.empty() )
            ix_tls_options.ciphers = tls_options.ciphers;

        server->setTLSOptions(ix_tls_options);
    }

    // Using the legacy IXWebsocketAPI API to acquire a shared_ptr to the ix::WebSocket instance.
    ix::WebSocketServer::OnConnectionCallback connection_callback =
        [dispatcher = dispatcher.get()](std::weak_ptr<ix::WebSocket> websocket,
                                        std::shared_ptr<ix::ConnectionState> cs) -> void {
        // Hold a shared_ptr to the WebSocket object until we see the close.
        std::shared_ptr<ix::WebSocket> ws = websocket.lock();

        // Client already gone or terminated? Weird...
        if ( ! ws || cs->isTerminated() )
            return;

        auto id = cs->getId();
        int remotePort = cs->getRemotePort();
        std::string remoteIp = cs->getRemoteIp();

        auto ixws = std::make_shared<IxWebSocketClient>(std::move(cs), ws);

        // These callbacks run in per client threads. The actual processing happens
        // on the main thread via a single WebSocketDemux instance.
        ix::OnMessageCallback message_callback = [dispatcher, id = std::move(id), remotePort,
                                                  remoteIp = std::move(remoteIp),
                                                  ixws = std::move(ixws)](const ix::WebSocketMessagePtr& msg) mutable {
            if ( msg->type == ix::WebSocketMessageType::Open ) {
                std::optional<std::string> application_name;
                auto it = msg->openInfo.headers.find("X-Application-Name");
                if ( it != msg->openInfo.headers.end() )
                    application_name = it->second;

                dispatcher->QueueForProcessing(WebSocketOpen{id, msg->openInfo.uri, msg->openInfo.protocol,
                                                             std::move(application_name), std::move(ixws)});
            }
            else if ( msg->type == ix::WebSocketMessageType::Message ) {
                dispatcher->QueueForProcessing(WebSocketMessage{id, msg->str});
            }
            else if ( msg->type == ix::WebSocketMessageType::Close ) {
                auto& ci = msg->closeInfo;
                dispatcher->QueueForProcessing(WebSocketClose{id, ci.code, std::move(ci.reason)});
            }
            else if ( msg->type == ix::WebSocketMessageType::Error ) {
                dispatcher->QueueForProcessing(WebSocketClose{id});
            }
        };

        ws->setOnMessageCallback(message_callback);
    };

    server->setOnConnectionCallback(connection_callback);

    const auto [success, reason] = server->listen();
    if ( ! success ) {
        zeek::reporter->Error("WebSocket: Unable to listen on %s:%d: %s", options.host.c_str(), options.port,
                              reason.c_str());
        return nullptr;
    }

    server->start();

    return std::make_unique<IXWebSocketServer>(std::move(dispatcher), std::move(server));
}


} // namespace zeek::cluster::websocket::detail::ixwebsocket

using namespace zeek::cluster::websocket::detail;

std::unique_ptr<WebSocketServer> zeek::cluster::websocket::detail::StartServer(
    std::unique_ptr<WebSocketEventDispatcher> dispatcher, const ServerOptions& options) {
    // Just delegate to the above IXWebSocket specific implementation.
    return ixwebsocket::StartServer(std::move(dispatcher), options);
}
