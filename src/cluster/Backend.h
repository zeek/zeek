// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/Flare.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {

class Val;
class FuncVal;

using ValPtr = IntrusivePtr<Val>;
using FuncValPtr = IntrusivePtr<FuncVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;

using ArgsSpan = Span<const ValPtr>;

namespace logging {
class WriterFrontend;

namespace detail {
struct LogWriteHeader;
}
} // namespace logging

namespace cluster {

namespace detail {

/**
 * Event class as received by and serializers.
 */
class Event {
public:
    // When an Event is published from script land, the handler is known
    // as FuncVal. When an Event is deserialized an EventHandler from
    // the registry is used so the event can be enqueued directly.
    //
    // It seems there's no direct translation between EventHandlerPtr and
    // FuncValPtr without going through the global scope or event registry,
    // so this is done via a variant.
    using FuncValOrEventHandler = std::variant<FuncValPtr, EventHandlerPtr>;

    /**
     * Constructor.
     */
    Event(FuncValOrEventHandler handler, zeek::Args args, double timestamp = 0.0)
        : handler(std::move(handler)), args(std::move(args)), timestamp(timestamp) {}

    FuncValOrEventHandler handler;
    zeek::Args args;
    double timestamp; // This should be more generic, like proper key-value
                      // metadata as a vector? Can delay until metadata is made
                      // accessible in script using a generic mechanism.
                      //
                      // This is encoded as vector(vector(count, any), ...) on
                      // the broker side.

    std::string_view HandlerName() const;
    const EventHandlerPtr& Handler() const { return std::get<EventHandlerPtr>(handler); }
    const FuncValPtr& FuncVal() const { return std::get<FuncValPtr>(handler); }
};
} // namespace detail

/**
 * Interface for a cluster backend implementing publish subscribe based
 * communication. Encoding of events should be done by the Serializer that
 * will be passed to the Factory function of BackendComponent.
 */
class Backend {
public:
    Backend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls)
        : event_serializer(std::move(es)), log_serializer(std::move(ls)) {}

    virtual ~Backend() = default;

    /**
     * Hook invoked after all scripts have been parsed.
     */
    void InitPostScript() { DoInitPostScript(); }

    /**
     * Method invoked from Cluster::Backend::__init() bif.
     */
    bool Init() { return DoInit(); }

    /**
     * Hook invoked when Zeek is about to terminate.
     */
    void Terminate() { DoTerminate(); }

    /**
     * Create a detail::Event instance given a event handler and the
     * script function arguments to it.
     *
     * @param handler
     * @param args
     * @param timestamp
     */
    std::optional<detail::Event> MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp = 0.0) const;

    /**
     * Publish \a event to topic \a topic.
     *
     * @param topic
     * @param event
     */
    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) {
        return DoPublishEvent(topic, event);
    }

    /**
     * Prepare a script-level event for publishing.
     *
     * This function is invoked from the \a Cluster::make_event() bif.
     *
     * The returned Val can be ClusterBackend specific. It could be a basic
     * script level record holding the required information.
     *
     * @param args FuncVal representing the event followed by its argument.
     *
     * @return An opaque RecordValPtr that can be passed to PublishEvent()
     */
    zeek::RecordValPtr MakeEvent(ArgsSpan args) { return DoMakeEvent(args); }

    /**
     * Send an event as produced by MakeEvent() to the given topic.
     *
     * The default implementation expects the \a Cluster::Event script type.
     *
     * @param topic a topic string associated with the message.
     * @param event an event RecordVal as produced by MakeEvent().
     * @return true if the message is sent successfully.
     */
    bool PublishEvent(const std::string& topic, const zeek::RecordValPtr& event) {
        return DoPublishEvent(topic, event);
    }

    /**
     * Register interest in messages that use a certain topic prefix.
     *
     * @param topic_prefix a prefix to match against remote message topics.
     * @return true if it's a new event subscription and it is now registered.
     */
    bool Subscribe(const std::string& topic_prefix) { return DoSubscribe(topic_prefix); }

    /**
     * Unregister interest in messages on a certain topic.
     *
     * @param topic_prefix a prefix previously supplied to Subscribe()
     * @return true if interest in topic prefix is no longer advertised.
     */
    bool Unsubscribe(const std::string& topic_prefix) { return DoUnsubscribe(topic_prefix); }

    /**
     * Publish multiple log writes.
     *
     * All log records belong to (the stream, filter, path) pair that is
     * described by \a header.
     *
     * @param header fixed information about the stream, writer, filter and the
     * schema.
     * @param path Separate from the header. One header may log to multiple paths,
     * but the header fields are constant.
     * @param records A span of logging::detail::LogRecords
     */
    bool PublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                          zeek::Span<zeek::logging::detail::LogRecord> records) {
        return DoPublishLogWrites(header, records);
    }

protected:
    /**
     * Process an incoming event message.
     */
    bool ProcessEventMessage(const std::string_view& topic, const std::string_view& format,
                             detail::byte_buffer_span payload);

    /**
     * Process an incoming log message.
     */
    bool ProcessLogMessage(const std::string_view& format, detail::byte_buffer_span payload);

private:
    /**
     * Called after all Zeek scripts have been loaded.
     *
     * A cluster backend should initialize itself based on script variables,
     * register any IO sources and possibly start connections. It should not
     * yet start any connections.
     */
    virtual void DoInitPostScript() = 0;

    /**
     * Called during Cluster::Backend::__init().
     *
     * Backend implementations should start connections with
     * remote systems or other nodes, open listening port or
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
     * Given arguments for the Cluster::make_event() function, create
     * a script-level record value that represents the event.
     *
     * The default implementation produces the \a Cluster::Event script type,
     * but may be overridden by implementations.
     *
     * @param args FuncVal representing the event followed by its argument.
     *
     * @return An opaque RecordValPtr that can be passed to PublishEvent()
     */
    virtual zeek::RecordValPtr DoMakeEvent(ArgsSpan args);

    /**
     * Send an event as produced by MakeEvent() to the given topic.
     *
     * The default implementation expects the \a Cluster::Event script type,
     * converts it to a cluster::detail::Event and publishes that.
     *
     * @param topic a topic string associated with the message.
     * @param event an event RecordVal as produced by MakeEvent().
     * @return true if the message is sent successfully.
     */
    virtual bool DoPublishEvent(const std::string& topic, const zeek::RecordValPtr& event);

    /**
     * Publish a cluster::detail::Event to the given topic.
     *
     * The default implementation serializes to a detail::byte_buffer and
     * calls DoPublishEvent() with it.
     *
     * This only exists for the existing Broker implementation so that it can
     * short-circuit serialization. Other backends should not need to implement
     * this.
     */
    virtual bool DoPublishEvent(const std::string& topic, const cluster::detail::Event& event);

    /**
     * Send a serialized cluster::detail::Event to the given topic.
     *
     * Semantics of this call are "fire-and-forget". An implementation should
     * ensure the message is enqueued for delivery, but may not have been send out
     * let alone received by any subscribers of topic when this call returns.
     *
     * @param topic a topic string associated with the message.
     * @param buf the serialized Event
     * @return true if the message has been published successfully.
     */
    virtual bool DoPublishEvent(const std::string& topic, const std::string& format,
                                const detail::byte_buffer& buf) = 0;

    /**
     * Register interest in messages that use a certain topic prefix.
     *
     * @param topic_prefix a prefix to match against remote message topics.
     * @return true if it's a new event subscription and it is now registered.
     */
    virtual bool DoSubscribe(const std::string& topic_prefix) = 0;

    /**
     * Unregister interest in messages on a certain topic.
     *
     * @param topic_prefix a prefix previously supplied to Subscribe()
     * @return true if interest in topic prefix is no longer advertised.
     */
    virtual bool DoUnsubscribe(const std::string& topic_prefix) = 0;

    /**
     * Serialize a log batch, then forward it to DoPublishLogWrites() below.
     *
     * This is provided as a virtual method so that the existing broker
     * implementation can provide a short-circuit serialization. Other backends
     * should not need to override this.
     *
     * @param header
     * @param records
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
     * ensure the message is enqueue for delivery, but may not have been send out
     * let alone received by the destination when this call returns.
     *
     * @param header The header describing the log.
     * @param buf The serialized log batch. This is the message payload.
     * @return true if the message has been published successfully.
     */
    virtual bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                                    detail::byte_buffer& buf) = 0;

    std::unique_ptr<EventSerializer> event_serializer;
    std::unique_ptr<LogSerializer> log_serializer;
};

/**
 * A cluster backend may receive event and log messages through threads.
 * The following structs can be used together with QueueForProcessing()
 * to enqueue these onto the main IO loop for processing.
 *
 * EventMessage and LogMessage are processed in a generic fashion in
 * Process(), while BackendMessage can be intercepted with
 * DoProcessBackendMessage().
 */

// A message on a topic was received.
struct EventMessage {
    std::string topic;
    std::string format;
    detail::byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

// Represents a received log message.
struct LogMessage {
    std::string format;
    detail::byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

// Represents a backend specific message.
struct BackendMessage {
    int tag;
    detail::byte_buffer payload;

    auto payload_span() const { return Span(payload.data(), payload.size()); };
};

using QueueMessage = std::variant<EventMessage, LogMessage, BackendMessage>;
using QueueMessages = std::vector<QueueMessage>;

/**
 * Support for backends that use background threads or invoke
 * callbacks on non-main threads.
 */
class ThreadedBackend : public Backend, public zeek::iosource::IOSource {
public:
    using Backend::Backend;

protected:
    /**
     * To be used by implementations to enqueue messages for processing on the IO loop.
     *
     * It's safe to call this method from other threads.
     */
    void QueueForProcessing(QueueMessages&& qmessage);

    void Process() override;

    double GetNextTimeout() override { return -1; }

    /**
     * The DoInit() implementation of ThreadedBackend
     * registers itself as a counting IO source that
     * keeps the IO loop alive.
     *
     * Classes deriving from ThreadedBackend should invoke
     * this method at some point, or register themselves
     * with the IO loop if needed.
     */
    bool DoInit() override;

    /**
     * The DoInitPostScript() implementation of ThreadedBackend
     * registers itself as a non-counting IO source.
     *
     * Classes deriving from ThreadedBackend should invoke
     * this method at some point, or register themselves
     * with the IO loop if needed.
     */
    void DoInitPostScript() override;

private:
    /**
     * Helper enum to avoid bool parameters.
     */
    enum class IOSourceCount { COUNT, DONT_COUNT };

    /**
     * Register this as IO source with the IO loop;
     */
    bool RegisterIOSource(IOSourceCount count);

    /**
     * Process a backend specific message queued as BackendMessage.
     */
    bool ProcessBackendMessage(int tag, detail::byte_buffer_span payload);

    /**
     * If a cluster backend produces messages of type BackendMessage,
     * this method will be invoked by the main thread to process it.
     */
    virtual bool DoProcessBackendMessage(int tag, detail::byte_buffer_span payload) { return false; };

    // Members used for communication with the main thread.
    std::mutex messages_mtx;
    std::vector<QueueMessage> messages;
    zeek::detail::Flare messages_flare;
};


// Cluster backend instance used for publish() and subscribe() calls.
extern Backend* backend;

} // namespace cluster
} // namespace zeek
