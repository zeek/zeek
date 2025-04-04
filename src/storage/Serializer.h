// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Val.h"

namespace zeek::storage {

class Serializer {
public:
    virtual ~Serializer() = default;
    virtual std::optional<util::byte_buffer> Serialize(ValPtr val) = 0;
    virtual zeek::expected<ValPtr, std::string> Unserialize(util::byte_buffer_span buf, TypePtr type) = 0;

protected:
    Serializer(std::string name) : name(std::move(name)) {}

private:
    std::string name;
};

} // namespace zeek::storage
