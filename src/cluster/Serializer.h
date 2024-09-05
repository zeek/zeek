// See the file "COPYING" in the main distribution directory for copyright.
//
// The serializer for events to be sent around in a Zeek cluster. Yes, yet
// another serializer...

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "zeek/Span.h"
#include "zeek/logging/Types.h"


namespace zeek {

template<class T>
class IntrusivePtr;

class Val;
using ValPtr = IntrusivePtr<Val>;

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace cluster {

namespace detail {
class Event;

using byte_buffer = std::vector<std::byte>;
} // namespace detail


/**
 * This class handles encoding of Events into byte buffers and back.
 *
 * An event and its parameters can be serialized as a message which
 * another node can unserialize and enqueue as an event.
 */
class EventSerializer {
public:
    EventSerializer(std::string name) : name(std::move(name)) {}

    virtual ~EventSerializer() = default;
    /**
     * Serialize an Event into the given buffer \a buf.
     *
     * @param buf
     * @param event
     *
     * @returns True on success, false in exceptional cases (e.g. unsupported serialization).
     */
    virtual bool SerializeEventInto(detail::byte_buffer& buf, const detail::Event& event) = 0;

    /**
     * Unserialize a message as Event.
     *
     * @param buf
     * @param size
     *
     * @returns The event or std::nullopt on error.
     */
    virtual std::optional<cluster::detail::Event> UnserializeEvent(const std::byte* buf, size_t size) = 0;

    /**
     * Return the name of the serializer - this should be included in message headers.
     */
    const std::string& Name() { return name; }

private:
    std::string name;
};

/**
 * Interface for a serializer for logging::LogRecord instances.
 */
class LogSerializer {
public:
    /**
     * Constructor.
     */
    explicit LogSerializer(std::string name) : name(std::move(name)){};

    virtual ~LogSerializer() = default;

    /**
     * Serialize all records into the given buffer.
     */
    virtual bool SerializeLogWriteInto(detail::byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                       zeek::Span<logging::detail::LogRecord> records) = 0;

    /**
     * Unserialize log writes from a given buffer.
     *
     * Not sure this is so clever for cap-n-proto style protocols
     * where the underlying buffer shouldn't be freed.
     */
    virtual std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(const std::byte* buf, size_t size) = 0;

    /**
     * Return the name of the serializer.
     */
    const std::string& Name() { return name; }

private:
    std::string name;
};

} // namespace cluster
} // namespace zeek
