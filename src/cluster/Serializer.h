// See the file "COPYING" in the main distribution directory for copyright.
//
// The serializer for events to be sent around in a Zeek cluster. Yes, yet
// another serializer...

#pragma once

#include <optional>
#include <vector>


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
 * another node can unserialize and enqueue.
 */
class Serializer {
public:
    virtual ~Serializer() = default;
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
     * Serialize a given Val into a byte_buffer.
     *
     * NOTE: This is to support Key-Value storage systems and possibly should live
     *       in its own Val serializer component?
     * NOTE: Should this return a std::variant with some error notification?
     *
     * @param buf
     * @param v The value to serialize.
     */
    virtual bool SerializeValInto(detail::byte_buffer& buf, const zeek::ValPtr& v) = 0;

    /**
     * Attempt to unserialize some data into a Val of a given type.
     *
     * NOTE: This is to support Key-Value storage systems and possibly should live
     *       in its own Val serializer component?
     *
     * NOTE: Should this return a std::variant with error notification?
     *
     * @param buf
     * @param size
     * @param type
     */
    virtual std::optional<zeek::ValPtr> UnserializeVal(const std::byte* buf, size_t size,
                                                       const zeek::TypePtr& type) = 0;
};

} // namespace cluster
} // namespace zeek
