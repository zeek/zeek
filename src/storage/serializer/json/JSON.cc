// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/serializer/json/JSON.h"

#include <algorithm>

#include "zeek/Func.h"

namespace zeek::storage::serializer::json {

std::string JSON::versioned_name = "JSONv1";

std::unique_ptr<Serializer> JSON::Instantiate() { return std::make_unique<JSON>(); }

JSON::JSON() : Serializer("JSON") {}

std::optional<byte_buffer> JSON::Serialize(ValPtr val) {
    static auto byte_converter = [](u_char c) { return std::byte(c); };

    byte_buffer buf;
    auto json = val->ToJSON();
    buf.reserve(json->Len() + versioned_name.size() + 1);

    std::transform(versioned_name.begin(), versioned_name.end(), std::back_inserter(buf), byte_converter);
    buf.push_back(static_cast<std::byte>(';'));
    std::transform(json->Bytes(), json->Bytes() + json->Len(), std::back_inserter(buf), byte_converter);

    return buf;
}

zeek::expected<ValPtr, std::string> JSON::Unserialize(byte_buffer_span buf, TypePtr type) {
    std::string_view text{reinterpret_cast<std::string::const_pointer>(buf.data()), buf.size()};

    auto semicolon = text.find(';');
    if ( semicolon == std::string::npos )
        return zeek::unexpected<std::string>("Version string missing");

    std::string_view version = std::string_view(text).substr(0, semicolon);
    if ( version != versioned_name )
        return zeek::unexpected<std::string>(util::fmt("Version doesn't match: %.*s vs %s",
                                                       static_cast<int>(version.size()), version.data(),
                                                       versioned_name.c_str()));

    return zeek::detail::ValFromJSON(text.substr(semicolon + 1), type, Func::nil);
}

} // namespace zeek::storage::serializer::json
