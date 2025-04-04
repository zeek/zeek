// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Val.h"

namespace zeek::storage {

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
    virtual std::optional<byte_buffer> Serialize(ValPtr val) = 0;

    /**
     * Unserializes a byte buffer into Zeek Val objects of a specific type.
     *
     * @param buf The byte data to unserialize.
     * @param type The Zeek script-level type to unserialize the data into.
     *
     * @return A zeek::expected containing either the unserialized Val data on success, or
     * a string containing an error message on failure.
     */
    virtual zeek::expected<ValPtr, std::string> Unserialize(byte_buffer_span buf, TypePtr type) = 0;

protected:
    Serializer(std::string name) : name(std::move(name)) {}

private:
    std::string name;
};

} // namespace zeek::storage
