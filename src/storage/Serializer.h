// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <string_view>

#include "zeek/Val.h"

namespace zeek::storage {

/**
 * Base class for a serializer used by storage backends.
 */
class Serializer {
public:
    /**
     * A function pointer to a string transformation function that backends can use to
     * force formatting on the serializer output.
     */
    using string_transform = std::function<std::string(std::string_view)>;

    virtual ~Serializer() = default;

    /**
     * Serializes Zeek Val data into another format.
     *
     * @param val The data to serialize.
     *
     * @param str_xform For string-based serializers (such as JSON), this provides a
     * function that can enforce specific formatting on the output during serializaiton.
     *
     * @return On success, a byte buffer containing the serialized data. std::nullopt will
     *  be returned on failure.
     */
    virtual std::optional<util::byte_buffer> Serialize(ValPtr val, string_transform str_xform = nullptr) = 0;

    /**
     * Unserializes a byte buffer into Zeek Val objects of a specific type.
     *
     * @param buf The byte data to unserialize.
     * @param type The Zeek script-level type to unserialize the data into.
     *
     * @return A zeek::expected containing either the unserialized Val data on success, or
     * a string containing an error message on failure.
     */
    virtual zeek::expected<ValPtr, std::string> Unserialize(util::byte_buffer_span buf, TypePtr type) = 0;

protected:
    Serializer(std::string name) : name(std::move(name)) {}
    std::string name;
};

} // namespace zeek::storage
