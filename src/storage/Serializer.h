// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Span.h"
#include "zeek/Val.h"

namespace zeek::storage {

namespace detail {
using byte_buffer = std::vector<std::byte>;
using byte_buffer_span = Span<const std::byte>;
} // namespace detail

/**
 * Base class for a serializer used by storage backends.
 */
class Serializer {
public:
    virtual ~Serializer() = default;

    /**
     * Serializes Zeek Val data into another format.
     *
     * @param val The data to serialize.
     *
     * @return On success, a byte buffer containing the serialized data. std::nullopt will
     *  be returned on failure.
     */
    virtual std::optional<detail::byte_buffer> Serialize(ValPtr val) = 0;

    /**
     * Unserializes a byte buffer into Zeek Val objects of a specific type.
     *
     * @param buf The byte data to unserialize.
     * @param type The Zeek script-level type to unserialize the data into.
     *
     * @return A zeek::expected containing either the unserialized Val data on success, or
     * a string containing an error message on failure.
     */
    virtual zeek::expected<ValPtr, std::string> Unserialize(detail::byte_buffer_span buf, TypePtr type) = 0;

protected:
    Serializer(std::string name) : name(std::move(name)) {}

private:
    std::string name;
};

} // namespace zeek::storage
