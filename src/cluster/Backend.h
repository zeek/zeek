// See the file "COPYING" in the main distribution directory for copyright.

// The interface for cluster backends and remote events.

#pragma once

#include <memory>
#include <optional>
#include <string_view>
#include <variant>

#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/Span.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"
#include "zeek/cluster/BifSupport.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"

namespace zeek {

namespace detail {
template<class Proc, class Work>
class OnLoopProcess;
}

namespace cluster {

namespace detail {

/**
 * Cluster event class.
 */
class Event {
public:
    /**
     * Constructor.
     */
    Event(const EventHandlerPtr& handler, zeek::Args args, zeek::detail::EventMetadataVectorPtr meta)
        : handler(handler), args(std::move(args)), meta(std::move(meta)) {}

    /**
     * Constructor.
     */
    [[deprecated]] Event(const EventHandlerPtr& handler, zeek::Args args, double timestamp = 0.0)
        : handler(handler), args(std::move(args)), meta(zeek::detail::MakeEventMetadataVector(timestamp)) {}

    /**
     * @return The name of the event.
     */
    std::string_view HandlerName() const { return handler->Name(); }

    /**
     * @return The event's handler.
     */
    const EventHandlerPtr& Handler() const { return handler; }

    /**
     * @return The event's arguments.
     */
    const zeek::Args& Args() const { return args; }
    /**
     * @return The event's arguments.
     */
    zeek::Args& Args() { return args; }

    /**
     * @return The network timestamp metadata of this event or -1.0 if not set.
     */
    double Timestamp() const;

    /**
     * Add metadata to this cluster event.
     *
     * The used metadata \a id has to be registered via the Zeek script-layer
     * function EventMetadata::register(), or via the C++ API
     * EventMgr::RegisterMetadata() during an InitPostScript() hook.
     *
     * Non-registered metadata will not be added and false is returned.
     *
     * @param id The enum value identifying the event metadata.
     * @param val The value to use.

     * @return true if \a val was was added, else false.
     */
    bool AddMetadata(const EnumValPtr& id, ValPtr val);

    /**
     * @return A pointer to the metadata vector, or nullptr if no Metadata has been added yet.
     */
    const zeek::detail::EventMetadataVector* Metadata() const { return meta.get(); }

private:
    EventHandlerPtr handler;
    zeek::Args args;
    zeek::detail::EventMetadataVectorPtr meta;
};

/**
 * Interface for processing cluster::Event instances received
 * on a given topic.
 *
 * An instances is injected into Backend instances to allow
 * modifying the behavior for received events. For instance,
 * for backends instantiated for WebSocket clients, events
 * should not be raised as Zeek events locally and instead
 * transmitted to the WebSocket client.
 */
class EventHandlingStrategy {
public:
    virtual ~EventHandlingStrategy() = default;

    /**
     * Method for processing a remote event received on the given topic.
     *
     * When handling the remote event fails, this method should return false.
     *
     * @param topic The topic on which the event was received.
     * @param ev The parsed event that was received.
     *
     * @return true if the remote event was handled successfully, else false.
     */
    bool ProcessEvent(std::string_view topic, Event e) { return DoProcessEvent(topic, std::move(e)); }

    /**
     * Method for enquing backend specific events.
     *
     * Some backend's may raise events destined for the local
     * scripting layer. That's usually wanted, but not always.
     * When the backend is instantiated for a WebSocket client,
     * local scripting layer should not raise events for the
     * WebSocket client.
     *
     * @param h The event handler to use.
     * @param args The event arguments.
     */
    void ProcessLocalEvent(EventHandlerPtr h, zeek::Args args) { DoProcessLocalEvent(h, std::move(args)); }

    /**
     * Process an error.
     *
     * @param tag A stringified structured error tag not further specified.
     * @param message A free form message with more context.
     */
    void ProcessError(std::string_view tag, std::string_view message) { return DoProcessError(tag, message); };

private:
    /**
     * Hook method for implementing ProcessEvent().
     *
     * @param topic The topic on which the event was received.
     * @param ev The parsed event that was received.
     *
     * @return true if the remote event was handled successfully, else false.
     */
    virtual bool DoProcessEvent(std::string_view topic, Event e) = 0;

    /**
     * Hook method for implementing ProcessLocalEvent().
     *
     * @param h The event handler to use.
     * @param args The event arguments.
     */
    virtual void DoProcessLocalEvent(EventHandlerPtr h, zeek::Args args) = 0;

    /**
     * Hook method for implementing ProcessError().
     *
     * @param tag A stringified structured error tag not further specified.
     * @param message A free form message with more context.
     */
    virtual void DoProcessError(std::string_view tag, std::string_view message) = 0;
};

/**
 * Strategy enqueueing events into this process's Zeek event loop.
 */
class LocalEventHandlingStrategy : public EventHandlingStrategy {
private:
    bool DoProcessEvent(std::string_view topic, Event e) override;
    void DoProcessLocalEvent(EventHandlerPtr h, zeek::Args args) override;
    void DoProcessError(std::string_view tag, std::string_view message) override;
};

/**
 * Validate that the provided args are suitable for handler.
 *
 * @param handler An event  handler.
 * @param args The provide arguments for the handler as a span.
 *
 * @return A zeek::Args instance if successful, else std::nullopt.
 */
std::optional<zeek::Args> check_args(const zeek::FuncValPtr& handler, zeek::ArgsSpan args);
} // namespace detail

/**
 * Interface for a cluster backend implementing publish/subscribe communication.
 * Serialization of events should be done using the serializers injected into
 * the constructor.
 */
class Backend {
public:
    virtual ~Backend() = default;

    /**
     * Hook invoked after all scripts have been parsed.
     */
    void InitPostScript() { DoInitPostScript(); }

    /**
     * Method invoked from the Cluster::Backend::__init() bif.
     *
     * @param nid The node identifier to use.
     */
    bool Init(std::string nid);

    /**
     * Hook invoked when Zeek is about to terminate.
     */
    void Terminate() { DoTerminate(); }

    /**
     * Create a cluster::detail::Event instance given an event handler and the
     * script function arguments to it.
     *
     * @param handler A function val representing an event handler.
     * @param args The arguments for the event handler.
     * @param timestamp The network time to add to the event as metadata.
     */
    std::optional<detail::Event> MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp = 0.0) const;

    /**
     * Publish a cluster::detail::Event instance to a given topic.
     *
     * The event is allowed to be modified by plugins, e.g. to add additional
     * metadata, modify the arguments, or rewrite it in other ways, too. The
     * caller will observe these changes on the event as it is passed by
     * reference.
     *
     * @param topic The topic string to publish the event to.
     * @param event The event to publish.
     *
     * @return true if the event was successfully published.
     */
    bool PublishEvent(const std::string& topic, cluster::detail::Event& event) { return DoPublishEvent(topic, event); }

    /**
     * Status codes for callbacks.
     */
    enum class CallbackStatus {
        Success,
        Error,
        NotImplemented,
    };

    /**
     * Information for subscription callbacks.
     */
    struct SubscriptionCallbackInfo {
        CallbackStatus status;              // The status of the operation.
        std::optional<std::string> message; // Optional message.
    };

    using SubscribeCallback =
        std::function<void(const std::string& topic_prefix, const SubscriptionCallbackInfo& info)>;

    /**
     * Register interest in messages that use a certain topic prefix.
     *
     * Invoking cb may happen while Subscribe() executes, for example if the
     * call to Subscribe() is synchronous, or an error is discovered before
     * submitting any work.
     *
     * @param topic_prefix a prefix to match against remote message topics.
     * @param cb callback invoked when the subscription was processed.
     * @return true if it's a new event subscription and it is now registered.
     */
    bool Subscribe(const std::string& topic_prefix, SubscribeCallback cb = SubscribeCallback()) {
        return DoSubscribe(topic_prefix, std::move(cb));
    }

    /**
     * Unregister interest in messages on a certain topic.
     *
     * @param topic_prefix a prefix previously supplied to Subscribe()
     * @return true if interest in topic prefix is no longer advertised.
     */
    bool Unsubscribe(const std::string& topic_prefix) { return DoUnsubscribe(topic_prefix); }

    /**
     * Information passed to a ready callback.
     */
    using ReadyCallbackInfo = SubscriptionCallbackInfo;

    using ReadyCallback = std::function<void(const ReadyCallbackInfo& info)>;

    /**
     * Register a "ready to publish" callback.
     *
     * Some cluster backend implementations may not be immediately ready for
     * publish operations. For example, ZeroMQ has sender-side subscription
     * filtering and discards messages until the XPUB socket learns about
     * subscriptions in a cluster.
     *
     * The callback mechanism allows backends to notify the caller that it
     * has now determined readiness for publish operations.
     *
     * Callers should be prepared that \a cb is invoked immediately as that
     * is the default implementation for DoReadyToPublishCallback().
     *
     * @param cb The callback to invoke when the backend is ready for publish operations.
     */
    void ReadyToPublishCallback(ReadyCallback cb) { DoReadyToPublishCallback(std::move(cb)); }

    /**
     * Publish multiple log records.
     *
     * All log records belong to the (stream, filter, path) tuple that is
     * described by \a header.
     *
     * @param header Fixed information about the stream, writer, filter and schema of the records.
     * @param records A span of logging::detail::LogRecords to be published.
     */
    bool PublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                          zeek::Span<zeek::logging::detail::LogRecord> records) {
        return DoPublishLogWrites(header, records);
    }

    /**
     * @return This backend's implementation name.
     */
    const std::string& Name() const { return name; }

    /**
     * @return This backend's implementation component tag.
     */
    const zeek::Tag& Tag() const { return tag; }

    /**
     * @return This backend's node identifier.
     */
    const std::string& NodeId() const { return node_id; }

protected:
    /**
     * Constructor.
     *
     * @param name The name corresponding to the component tag.
     * @param es The event serializer to use.
     * @param ls The log batch serializer to use.
     * @param ehs The event handling strategy to use for this backend.
     */
    Backend(std::string_view name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
            std::unique_ptr<detail::EventHandlingStrategy> ehs);

    /**
     * Enqueue an event to be raised to this process Zeek scripting layer.
     *
     * When a backend is used for a WebSocket client connection, events
     * raised through this method are blackholed.
     *
     * @param h The event handler.
     * @param args The event arguments.
     */
    void EnqueueEvent(EventHandlerPtr h, zeek::Args args);

    /**
     * Process a cluster event.
     *
     * This method is called by ProcessEventMessage() and delegates
     * to the event handling strategy. It should only be used by
     * backends implementing their own serialization format. Other
     * backends should not have a use for this and call ProcessEventMessage()
     * directly instead.
     *
     * @param topic The topic on which the event was received.
     * @param e The event as cluster::detail::Event.
     */
    bool ProcessEvent(std::string_view topic, detail::Event e);

    /**
     * An error happened, pass it to the event handling strategy.
     *
     * Errors are not necessarily in response to a publish operation, but
     * can also be raised when receiving messages. E.g. if received data
     * couldn't be properly parsed.
     *
     * @param tag A stringified structured error tag not further specified.
     * @param message A free form message with more context.
     */
    void ProcessError(std::string_view tag, std::string_view message);

    /**
     * Process an incoming event message.
     */
    bool ProcessEventMessage(std::string_view topic, std::string_view format, byte_buffer_span payload);

    /**
     * Process an incoming log message.
     */
    bool ProcessLogMessage(std::string_view format, byte_buffer_span payload);

    /**
     * Set this backend's identifier to the given value.
     *
     * This may be called by backend implementations during DoInitPostScript() if
     * their node identifier is generated internally.
     *
     * @param nid
     */
    void SetNodeId(std::string nid);

private:
    /**
     * Called after all Zeek scripts have been loaded.
     *
     * A cluster backend should initialize itself based on script variables,
     * register any IO sources, etc. It should not yet start any connections, that
     * should happen in DoInit() instead.
     */
    virtual void DoInitPostScript() = 0;

    /**
     * Called from Cluster::Backend::__init().
     *
     * Backend implementations should start connections with
     * remote systems or other nodes, open listening ports or
     * do whatever is needed to be functional.
     */
    virtual bool DoInit() = 0;

    /**
     * Called at termination time.
     *
     * This should be used to shut down connectivity. Any last messages
     * to be published should be sent from script land, rather than in
     * DoTerminate(). A backend may wait for a bounded and configurable
     * amount of time to flush any last messages out.
     */
    virtual void DoTerminate() = 0;

    /**
     * Publish a cluster::detail::Event to the given topic.
     *
     * The default implementation serializes to a byte_buffer and
     * calls DoPublishEvent() with the resulting buffer.
     *
     * This hook method only exists for the existing Broker implementation that
     * short-circuits serialization. Other backends should not override this.
     */
    virtual bool DoPublishEvent(const std::string& topic, cluster::detail::Event& event);

    /**
     * Send a serialized cluster::detail::Event to the given topic.
     *
     * Semantics of this call are "fire-and-forget". An implementation should
     * ensure the message is enqueued for delivery, but may not have been sent out
     * let alone received by any subscribers of the topic when this call returns.
     *
     * If the backend has not established a connection, the published message is
     * allowed to be discarded.
     *
     * @param topic a topic string associated with the message.
     * @param format the format/serializer used for serialization of the message payload.
     * @param buf the serialized Event.
     * @return true if the message has been published successfully.
     */
    virtual bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) = 0;

    /**
     * Register interest in messages that use a certain topic prefix.
     *
     * If the backend hasn't yet established a connection, any subscriptions
     * should be queued until they can be processed. If a callback is given,
     * it should be called once the subscription can be determined to be
     * active. The callback has to be invoked from Zeek's main thread. If
     * the backend does not implement callbacks, it should invoke the callback
     * with CallbackStatus::NotImplemented, which will act as success, but
     * provides a way to distinguish behavior.
     *
     * @param topic_prefix a prefix to match against remote message topics.
     * @param cb callback to invoke when the subscription is active
     *
     * @return true if it's a new event subscription and now registered.
     */
    virtual bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) = 0;

    /**
     * Unregister interest in messages on a certain topic.
     *
     * @param topic_prefix a prefix previously supplied to Subscribe()
     * @return true if interest in topic prefix is no longer advertised.
     */
    virtual bool DoUnsubscribe(const std::string& topic_prefix) = 0;

    /**
     * Register a "ready to publish" callback.
     *
     * @param cb The callback to invoke when the backend is ready for publish operations.
     */
    virtual void DoReadyToPublishCallback(ReadyCallback cb);

    /**
     * Serialize a log batch, then forward it to DoPublishLogWrites() below.

     * The default implementation serializes to a byte_buffer and
     * calls DoPublishLogWrites() with the resulting buffer.
     *
     * This hook method only exists for the existing Broker implementation that
     * short-circuits serialization. Other backends should not override this.
     *
     * @param header The header describing the writer frontend where the records originate from.
     * @param records Records to be serialized.
     *
     * @return true if the message has been published successfully.
     */
    virtual bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                    zeek::Span<zeek::logging::detail::LogRecord> records);

    /**
     * Send out a serialized log batch.
     *
     * A backend implementation may use the values from \a header to
     * construct a topic to write the logs to.
     *
     * Semantics of this call are "fire-and-forget". An implementation should
     * ensure the message is enqueued for delivery, but may not have been sent out
     * let alone received by the destination when this call returns.
     *
     * Sharding log writes to multiple receivers (logger nodes) is backend specific.
     * Broker, for example, involves Zeek script layer cluster pool concepts.
     * Other backends may use appropriate native mechanisms that may be more
     * efficient.
     *
     * @param header the header describing the writer frontend where the records originate from.
     * @param format the format/serializer used for serialization of the message payload.
     * @param buf the serialized log batch. This is the message payload.
     * @return true if the message has been published successfully.
     */
    virtual bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                                    byte_buffer& buf) = 0;

    std::string name;
    zeek::Tag tag;
    std::unique_ptr<EventSerializer> event_serializer;
    std::unique_ptr<LogSerializer> log_serializer;
    std::unique_ptr<detail::EventHandlingStrategy> event_handling_strategy;

    /**
     * The backend's instance cluster node identifier.
     */
    std::string node_id;
};

/**
 * A cluster backend may receive event and log messages asynchronously
 * through threads. The following structs can be used with QueueForProcessing()
 * to enqueue these messages onto the main IO loop for processing.
 *
 * EventMessage and LogMessage are processed in a generic fashion in
 * the Process() method. The BackendMessage can be intercepted with
 * DoProcessBackendMessage(). DoProcessBackendMessage() is guaranteed
 * to run on Zeek's main thread.
 */

/**
 * A message on a topic for events was received.
 */
struct EventMessage {
    std::string topic;
    std::string format;
    byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

/**
 * A message that represents log records.
 */
struct LogMessage {
    std::string format;
    byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

/**
 * A backend specific message.
 *
 * This provides a mechanism to transfer auxiliary information
 * from a background thread to Zeek's main thread.
 */
struct BackendMessage {
    int tag;
    byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

using QueueMessage = std::variant<EventMessage, LogMessage, BackendMessage>;

/**
 * Support for backends that use background threads or invoke
 * callbacks on non-main threads.
 */
class ThreadedBackend : public Backend {
protected:
    /**
     * Constructor.
     */
    ThreadedBackend(std::string_view name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                    std::unique_ptr<detail::EventHandlingStrategy> ehs);

    /**
     * To be used by implementations to enqueue messages for processing on the IO loop.
     *
     * It's safe to call this method from any thread before ThreadedBackend's
     * DoTerminate() implementation is invoked.
     *
     * @param messages Messages to be enqueued.
     */
    void QueueForProcessing(QueueMessage&& messages);

    /**
     * The default DoInit() implementation of ThreadedBackend
     * registers itself as a counting IO source to keep the IO
     * loop alive after initialization.
     *
     * Classes deriving from ThreadedBackend and providing their
     * own DoInit() method should invoke the ThreadedBackend's
     * implementation to register themselves as a counting
     * IO source with the IO loop.
     */
    bool DoInit() override;

    /**
     * Common DoTerminate() functionality for threaded backends.
     *
     * The default DoTerminate() implementation of ThreadedBackend
     * runs OnLoop's Process() once to drain any pending messages, then
     * closes and unsets it.
     *
     * Classes deriving from ThreadedBackend need to ensure that all threads
     * calling QeueuForProcessing() have terminated before invoking the
     * ThreadedBackend's DoTerminate() implementation.
     */
    void DoTerminate() override;

private:
    /**
     * Process a backend specific message queued as BackendMessage.
     */
    bool ProcessBackendMessage(int tag, byte_buffer_span payload);

    /**
     * If a cluster backend produces messages of type BackendMessage,
     * this method will be invoked by the main thread to process it.
     */
    virtual bool DoProcessBackendMessage(int tag, byte_buffer_span payload) { return false; };

    /**
     * Hook method for OnLooProcess.
     */
    void Process(QueueMessage&& messages);

    // Allow access to Process(QueueMessages)
    friend class zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>;

    // Members used for communication with the main thread.
    zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>* onloop = nullptr;
};


// Cluster backend instance used for publish() and subscribe() calls.
extern Backend* backend;

} // namespace cluster
} // namespace zeek
