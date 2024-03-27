// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string_view>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"

namespace zeek {

class FuncVal;
using FuncValPtr = IntrusivePtr<FuncVal>;

namespace cluster {

namespace detail {

/**
 * Event class as received by and serializers.
 */
class Event {
public:
    // When an Event is published from script land, there's access to a FuncVal.
    // When it is de-serialized, and EventHandler should be set so that the
    // resulting Event instance can be enqueued directly.
    //
    // It seems there's no direct translation between EventHandlerPtr and
    // FuncValPtr without going through global scope or the event registry.
    using FuncValOrEventHandler = std::variant<FuncValPtr, EventHandlerPtr>;

    /**
     * Constructor.
     */
    Event(FuncValOrEventHandler handler, zeek::Args args, double timestamp = 0.0)
        : handler(std::move(handler)), args(std::move(args)), timestamp(timestamp) {}

    FuncValOrEventHandler handler;
    // TODO: Make this some && accessor so we can move args out of Event.
    zeek::Args args;
    double timestamp; // This should be more generic, like proper key-value
                      // metadata? Can delay until metadata is made accessible
                      // in script using a generic mechanism.

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
     * Helper to publish an event directly BIFs.
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
     * Prepare an event with its argument for publishing.
     *
     * The returned Val can be ClusterBackend specific. It could be an actual record,
     * and opaque value, etc.
     *
     * XXX: I don't quite get why there is `make_event()` or if it's useful, unless
     *      maybe for debugging. This seems to introduce extra overhead, unless there's
     *      some idea of re-using a prepared event, but even then it results in
     *      some amount of overhead.
     *
     * @param args Holds the event as FuncValPtr, followed arguments to be used.
     *
     * @return An opaque ValPtr that can be passed to PublishEvent()
     */
    virtual zeek::ValPtr MakeEvent(const zeek::Args& args) = 0;

    /**
     * Send an event as produced by MakeEvent() to the given topic.
     *
     * @param topic a topic string associated with the message.
     * @param event an event Val as produced by MakeEvent().
     * @return true if the message is sent successfully.
     */
    virtual bool PublishEvent(const std::string& topic, const zeek::ValPtr& event) = 0;

    /**
     * Send an event to the given topic.
     *
     * This should be the lowest level entry point. The common
     * Publish(const zeek::Args& args) method send data here.
     *
     * @param topic a topic string associated with the message.
     * @param event the Event to publish to the given topic.
     * @return true if the message is sent successfully.
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
};

// Cluster backend instance used for publish() and subscribe() calls.
extern Backend* backend;

} // namespace cluster
} // namespace zeek
