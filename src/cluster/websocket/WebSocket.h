// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace zeek {

namespace detail {

template<class Proc, class Work>
class OnLoopProcess;
}

namespace cluster {

class Backend;

namespace websocket {


/**
 * Library independent interface for a WebSocket client.
 *
 * All methods should be safe to be called from Zeek's
 * main thread, though some may fail if the client has vanished
 * or vanishes during an operation.
 */
class WebSocketClient {
public:
    virtual ~WebSocketClient() = default;

    /**
     * @returns true if the WebSocket client has terminated
     */
    virtual bool IsTerminated() const = 0;

    /**
     * Close the WebSocket connection with the given code/reason.
     */
    virtual void Close(uint16_t code = 1000, const std::string& reason = "Normal closure") = 0;

    /**
     * Information about the send operation.
     */
    struct SendInfo {
        bool success;
    };

    /**
     * Thread safe sending.
     *
     * This might be called from Zeek's main thread and
     * must be safe to be called whether or not the connection
     * with the client is still alive.
     *
     * @param sv The buffer to send as a WebSocket message.
     */
    virtual SendInfo SendText(std::string_view sv) = 0;

    /**
     * Send an error in Broker JSON/v1 format to the client.
     */
    SendInfo SendError(std::string_view code, std::string_view ctx);

    /**
     * Send an ACK message Broker JSON/v1 format to the client.
     */
    SendInfo SendAck(std::string_view endpoint, std::string_view version);

    /**
     * @return - has an ACK been sent to the client?
     */
    bool IsAcked() const { return acked; }

    /**
     * @return The WebSocket client's identifier.
     */
    virtual const std::string& getId() = 0;

    /**
     * @return The WebSocket client's remote IP address.
     */
    virtual const std::string& getRemoteIp() = 0;

    /**
     * @return The WebSocket client's remote port.
     */
    virtual int getRemotePort() = 0;

    /**
     * Store the client's subscriptions as "not active".
     */
    void SetSubscriptions(const std::vector<std::string>& topic_prefixes);

    /**
     * @return The client's subscriptions.
     */
    const std::vector<std::string>& GetSubscriptions() const;

    /**
     * Store the client's subscriptions as "not active".
     */
    void SetSubscriptionActive(std::string& topic_prefix);

    /**
     * @return true if all subscriptions have an active status.
     */
    bool AllSubscriptionsActive() const;

private:
    bool acked = false;
    std::map<std::string, bool> subscriptions_state;
    std::vector<std::string> subscriptions;
};

// An new WebSocket client connected. Client is locally identified by `id`.
struct WebSocketOpen {
    std::string id;
    std::shared_ptr<WebSocketClient> wsc;
};

// A WebSocket client disconnected.
struct WebSocketClose {
    std::string id;
};

// A WebSocket client send a message.
struct WebSocketMessage {
    std::string id;
    std::string msg;
};

// Produced internally when a WebSocket client's
// subscription has completed.
struct WebSocketSubscribeFinished {
    std::string id;
    std::string topic_prefix;
};

using WebSocketEvent = std::variant<WebSocketOpen, WebSocketSubscribeFinished, WebSocketClose, WebSocketMessage>;

struct WebSocketSendReply {
    std::shared_ptr<WebSocketClient> wsc;
    std::string msg;
};

struct WebSocketCloseReply {
    std::shared_ptr<WebSocketClient> wsc;
    uint16_t code = 1000;
    std::string reason = "Normal closure";
};

using WebSocketReply = std::variant<WebSocketSendReply, WebSocketCloseReply>;


class ReplyMsgThread;

/**
 * Handle events produced by WebSocket clients.
 *
 * Any thread may call QueueForProcessing(). Process() runs
 * on Zeek's main thread.
 */
class WebSocketEventDispatcher {
public:
    WebSocketEventDispatcher();

    ~WebSocketEventDispatcher();

    /**
     * Called shutting down a WebSocket server.
     */
    void Terminate();

    /**
     * Queue the given WebSocket event to be processed on Zeek's main loop.
     *
     * @param work The WebSocket event to process.
     */
    void QueueForProcessing(WebSocketEvent&& event);

    /**
     * Send a reply to the given websocket client.
     *
     * The dispatcher has an internal thread for serializing
     * and sending out the event.
     */
    void QueueReply(WebSocketReply&& reply);

private:
    /**
     * Main processing function of the dispatcher.
     *
     * This runs on Zeek's main thread.
     */
    void Process(WebSocketEvent&& event);

    void Process(WebSocketOpen& open);
    void Process(WebSocketSubscribeFinished& fin);
    void Process(WebSocketMessage& msg);
    void Process(WebSocketClose& close);


    /**
     * Data structure for tracking WebSocket clients.
     */
    struct WebSocketClientEntry {
        std::string id;
        std::shared_ptr<WebSocketClient> wsc;
        std::shared_ptr<zeek::cluster::Backend> backend;
        uint64_t msg_count = 0;
        std::list<WebSocketMessage> queue;
    };


    void HandleSubscriptions(WebSocketClientEntry& entry, std::string buf);
    void HandleEvent(WebSocketClientEntry& entry, std::string buf);

    // Allow access to Process(WebSocketEvent)
    friend zeek::detail::OnLoopProcess<WebSocketEventDispatcher, WebSocketEvent>;

    // Clients that this dispatcher is tracking.
    std::map<std::string, WebSocketClientEntry> clients;

    // Connector to the IO loop.
    zeek::detail::OnLoopProcess<WebSocketEventDispatcher, WebSocketEvent>* onloop = nullptr;

    // Thread replying to clients. Zeek's threading manager takes ownership.
    ReplyMsgThread* reply_msg_thread = nullptr;
};

/**
 * An abstract WebSocket server.
 */
class WebSocketServer {
public:
    WebSocketServer(std::unique_ptr<WebSocketEventDispatcher> demux) : dispatcher(std::move(demux)) {}
    virtual ~WebSocketServer() = default;

    /**
     * Stop this server.
     */
    void Terminate() {
        dispatcher->Terminate();

        DoTerminate();
    }

    WebSocketEventDispatcher& Dispatcher() { return *dispatcher; }

private:
    /**
     * Hook to be implemented when a server is terminated.
     */
    virtual void DoTerminate() = 0;

    std::unique_ptr<WebSocketEventDispatcher> dispatcher;
};


/**
 * TLS configuration for a WebSocket server.
 */
struct TLSOptions {
    bool enable = true;
    bool enable_peer_verification = false;
    std::string cert_file;
    std::string key_file;
    std::string ca_file;
    std::string ciphers;
};

struct ServerOptions {
    std::string host;
    int port = -1;
    int ping_interval = 5;
    int max_connections = 100;
    bool per_message_deflate = false;
};


/**
 * Start a WebSocket server.
 *
 * @param dispatcher The dispatcher to use for the server.
 * @param options Options for the server.
 *
 * @return Pointer to a new WebSocketServer instance or nullptr on error.
 */
std::unique_ptr<WebSocketServer> StartServer(std::unique_ptr<WebSocketEventDispatcher> dispatcher,
                                             const ServerOptions& options, const TLSOptions& tls_options);

} // namespace websocket
} // namespace cluster
} // namespace zeek
