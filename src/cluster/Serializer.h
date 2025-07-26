// See the file "COPYING" in the main distribution directory for copyright.

// Interfaces to be implemented by event and log serializer components.

#pragma once

#include <optional>
#include <span>
#include <string>

#include "zeek/logging/Types.h"

namespace zeek::cluster {

namespace detail {
class Event;
} // namespace detail

/**
 * This class handles encoding of events into byte buffers and back.
 *
 * An event and its parameters can be serialized as a message which
 * another node can unserialize and then enqueue as an event.
 */
class EventSerializer {
public:
    virtual ~EventSerializer() = default;

    /**
     * Serialize an event into the given byte buffer.
     *
     * @param buf The buffer to use for serialization.
     * @param event The event to serialize.
     *
     * @returns True on success, false in exceptional cases (e.g. unsupported serialization).
     */
    virtual bool SerializeEvent(byte_buffer& buf, const detail::Event& event) = 0;

    /**
     * Unserialize an event from a given byte buffer.
     *
     * @param buf A span representing a received remote event.
     *
     * @returns The event, or std::nullopt on error.
     */
    virtual std::optional<cluster::detail::Event> UnserializeEvent(byte_buffer_span buf) = 0;

    /**
     * @returns The name of this event serializer instance.
     */
    const std::string& Name() { return name; }

protected:
    /**
     * Constructor.
     */
    EventSerializer(std::string name) : name(std::move(name)) {}

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
    explicit LogSerializer(std::string name) : name(std::move(name)) {};

    virtual ~LogSerializer() = default;

    /**
     * Serialize log records into a byte buffer.
     *
     * @param buf The buffer to serialize into.
     * @param header The log batch header.
     * @param records The actual log writes.
     */
    virtual bool SerializeLogWrite(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                   std::span<logging::detail::LogRecord> records) = 0;

    /**
     * Unserialize log writes from a given byte buffer.
     *
     * @param buf The span representing received log writes.
     */
    virtual std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(byte_buffer_span buf) = 0;

    /**
     * @returns The name of this log serializer instance.
     */
    const std::string& Name() { return name; }

private:
    std::string name;
};

} // namespace zeek::cluster
