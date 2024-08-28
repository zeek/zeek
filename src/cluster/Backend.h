// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string_view>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"
#include "zeek/logging/WriterBackend.h"

namespace zeek {

class FuncVal;
using FuncValPtr = IntrusivePtr<FuncVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;

using ArgsSpan = Span<const ValPtr>;

namespace logging {
class WriterFrontend;

namespace detail {
class LogWriteHeader;
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
    // as FuncVal. When an Event is deserialized, and EventHandler from
    // the registry is used so the event can be enqueued directly.
    // resulting Event instance can be enqueued directly.
    //
    // It seems there's no direct translation between EventHandlerPtr and
    // FuncValPtr without going through the global scope or the event registry.
    using FuncValOrEventHandler = std::variant<FuncValPtr, EventHandlerPtr>;

    /**
     * Constructor.
     */
    Event(FuncValOrEventHandler handler, zeek::Args args, double timestamp = 0.0)
        : handler(std::move(handler)), args(std::move(args)), timestamp(timestamp) {}

    FuncValOrEventHandler handler;
    zeek::Args args;
    double timestamp; // This should be more generic, like proper key-value
                      // metadata? Can delay until metadata is made accessible
                      // in script using a generic mechanism.
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
    virtual ~Backend() = default;

    /**
     * Hook invoked after all scripts have been parsed.
     *
     * A cluster backend should initialize itself based on script variables,
     * register any IO sources and possibly start connections with a central
     * broker or peers.
     */
    virtual void InitPostScript() = 0;

    /**
     * Hook invoked when Zeek is about to terminate.
     */
    virtual void Terminate() = 0;

    /**
     * Helper to publish an event directly from BiFs
     *
     * This helper expects args to hold a FuncValPtr followed by the arguments, or followed
     * by a prepared "event" as created with MakeEvent().
     *
     * @return true if the message is sent successfully.
     *
     * @param args: The args, either [topic, event(FuncValPtr), args...] or [topic, opaque event]
     */
    bool PublishEvent(const zeek::Args& args);

    /**
     * Create a detail::Event instance given a event handler script function arguments to it.
     */
    detail::Event MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp = 0.0) const;

    /**
     * Prepare a script-level event.
     *
     * The returned Val can be ClusterBackend specific. It could be a basic
     * script level record or vector, or an opaque value.
     *
     * This function is invoked from the \a Cluster::make_event() bif.
     *
     * @param args FuncVal representing the event and its argument.
     * @param last
     *
     * @return An opaque ValPtr that can be passed to PublishEvent()
     */
    virtual zeek::RecordValPtr MakeEvent(ArgsSpan args);

    /**
     * Send an event as produced by MakeEvent() to the given topic.
     *
     * The default implementation expects the Cluster::Event script
     * type.
     *
     * @param topic a topic string associated with the message.
     * @param event an event RecordVal as produced by MakeEvent().
     * @return true if the message is sent successfully.
     */
    virtual bool PublishEvent(const std::string& topic, const zeek::ValPtr& event);

    /**
     * Send a cluster::detail::Event to the given topic.
     *
     * @param topic a topic string associated with the message.
     * @param event the Event to publish to the given topic.
     * @return true if the message has been published successfully.
     */
    virtual bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) = 0;

    /**
     * Register interest in messages that use a certain topic prefix.
     *
     * @param topic_prefix a prefix to match against remote message topics.
     * @return true if it's a new event subscription and it is now registered.
     */
    virtual bool Subscribe(const std::string& topic_prefix) = 0;

    /**
     * Unregister interest in messages on a certain topic.
     *
     * @param topic_prefix a prefix previously supplied to Subscribe()
     * @return true if interest in topic prefix is no longer advertised.
     */
    virtual bool Unsubscribe(const std::string& topic_prefix) = 0;

    /**
     * Publish multiple log writes.
     *
     * All log records belong to (the stream, filter, path) pair that is
     * described by \a header.
     *
     * @param header fixed information about the stream, writer, filter and the schema.
     * @param path Separate from the header. One header may log to multiple paths, but the header fields are constant.
     * @param records A span of logging::detail::LogRecords
     */
    virtual bool PublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                  zeek::Span<zeek::logging::detail::LogRecord> records) = 0;

    /**
     * Enable receiving of logs? Do we need an API or can that be done
     * on a per plugin basis? Maybe we want to inject the logging manager
     * where consumed messages can be pushed instead of coing via zeek::log_mgr
     * directly?
     */
};

// Cluster backend instance used for publish() and subscribe() calls.
extern Backend* backend;

} // namespace cluster
} // namespace zeek