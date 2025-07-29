// See the file "COPYING" in the main distribution directory for copyright.

// Val-based representation of an event for cluster communication.

#pragma once

#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"

namespace zeek::cluster {

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

    /**
     * Move data out of this event as preparation for Enqueue()
     */
    std::tuple<zeek::EventHandlerPtr, zeek::Args, zeek::detail::EventMetadataVectorPtr> Take() &&;

private:
    EventHandlerPtr handler;
    zeek::Args args;
    zeek::detail::EventMetadataVectorPtr meta;
};


} // namespace zeek::cluster
