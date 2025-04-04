// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/serializer/json/JSON.h"

#include "zeek/Func.h"

namespace zeek::storage::serializer::json {

std::unique_ptr<Serializer> JSON::Instantiate() { return std::make_unique<JSON>(); }

JSON::JSON() : Serializer("JSON") {}

std::optional<byte_buffer> JSON::Serialize(ValPtr val) {
    byte_buffer buf;
    auto json = val->ToJSON();
    buf.reserve(json->Len());

    std::transform(json->Bytes(), json->Bytes() + json->Len(), std::back_inserter(buf),
                   [](u_char c) { return std::byte(c); });

    return buf;
}

zeek::expected<ValPtr, std::string> JSON::Unserialize(byte_buffer_span buf, TypePtr type) {
    std::string_view text{reinterpret_cast<std::string::const_pointer>(buf.data()), buf.size()};
    return zeek::detail::ValFromJSON(text, type, Func::nil);
}

} // namespace zeek::storage::serializer::json
