// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <optional>
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

namespace websocket::detail {


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
    std::vector<std::string> GetSubscriptions() const;

    /**
     * Store the client's subscriptions as "not active".
     */
    void SetSubscriptionActive(const std::string& topic_prefix);

    /**
     * @return true if all subscriptions have an active status.
     */
    bool AllSubscriptionsActive() const;

private:
    bool acked = false;
    std::map<std::string, bool> subscriptions_state;
};

// An new WebSocket client connected. Client is locally identified by `id`.
struct WebSocketOpen {
    std::string id;
    std::string uri;
    std::string protocol;
    std::optional<std::string> application_name;
    std::shared_ptr<WebSocketClient> wsc;
};

// A WebSocket client disconnected.
struct WebSocketClose {
    std::string id;
    uint16_t code;
    std::string reason;
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

// Internally created when the backend of a Websocket client is ready.
struct WebSocketBackendReadyToPublish {
    std::string id;
};

using WebSocketEvent = std::variant<WebSocketOpen, WebSocketSubscribeFinished, WebSocketClose, WebSocketMessage,
                                    WebSocketBackendReadyToPublish>;

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
    /**
     * Constructor.
     *
     * @param ident A string identifying this dispatcher instance. Used in metrics.
     * @param queue_size Maximum queue size before events are stalled.
     */
    WebSocketEventDispatcher(const std::string& ident, size_t queue_size);

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
    void Process(const WebSocketEvent& event);

    void Process(const WebSocketOpen& open);
    void Process(const WebSocketSubscribeFinished& fin);
    void Process(const WebSocketBackendReadyToPublish& ready);
    void Process(const WebSocketMessage& msg);
    void Process(const WebSocketClose& close);


    /**
     * Data structure for tracking WebSocket clients.
     */
    struct WebSocketClientEntry {
        std::string id;
        std::shared_ptr<WebSocketClient> wsc;
        std::shared_ptr<zeek::cluster::Backend> backend;
        std::optional<std::string> application_name; // The value from the HTTP X-Application-Name header, if any.
        bool ready_to_publish = false;
        uint64_t msg_count = 0;
        std::list<WebSocketMessage> queue;
    };


    void HandleSubscriptions(WebSocketClientEntry& entry, std::string_view buf);

    // Raise the websocket_client_added event and send the ack to the client contained in entry.
    void HandleSubscriptionsActive(const WebSocketClientEntry& entry);

    void HandleEvent(WebSocketClientEntry& entry, std::string_view buf);

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
    std::optional<std::string> cert_file;
    std::optional<std::string> key_file;
    bool enable_peer_verification = false;
    std::string ca_file;
    std::string ciphers;

    /**
     * Is TLS enabled?
     */
    bool TlsEnabled() const { return cert_file.has_value() && key_file.has_value(); }

    bool operator==(const TLSOptions& o) const {
        return cert_file == o.cert_file && key_file == o.key_file &&
               enable_peer_verification == o.enable_peer_verification && ca_file == o.ca_file && ciphers == o.ciphers;
    }
};

/**
 * Options for a WebSocket server.
 */
struct ServerOptions {
    std::string host;
    uint16_t port = 0;
    int ping_interval_seconds = 5;
    int max_connections = 100;
    bool per_message_deflate = false;
    size_t max_event_queue_size = 32;
    struct TLSOptions tls_options;

    bool operator==(const ServerOptions& o) const {
        return host == o.host && port == o.port && ping_interval_seconds == o.ping_interval_seconds &&
               max_connections == o.max_connections && per_message_deflate == o.per_message_deflate &&
               max_event_queue_size == o.max_event_queue_size && tls_options == o.tls_options;
    }
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
                                             const ServerOptions& options);

} // namespace websocket::detail
} // namespace cluster
} // namespace zeek
