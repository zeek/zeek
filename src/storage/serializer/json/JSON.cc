// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/serializer/json/JSON.h"

#include "zeek/Func.h"

namespace zeek::storage::serializer::json {

std::unique_ptr<Serializer> JSON::Instantiate() { return std::make_unique<JSON>(); }

JSON::JSON() : Serializer("JSON") { versioned_name = util::fmt("%sv%d", name.c_str(), Val::JSON_VERSION); }

std::optional<util::byte_buffer> JSON::Serialize(ValPtr val) {
    static auto byte_converter = [](u_char c) { return std::byte(c); };

    std::string version = versioned_name + ";";

    util::byte_buffer buf;
    auto json = val->ToJSON();
    buf.reserve(json->Len() + version.size());

    std::transform(version.begin(), version.end(), std::back_inserter(buf), byte_converter);
    std::transform(json->Bytes(), json->Bytes() + json->Len(), std::back_inserter(buf), byte_converter);

    return buf;
}

zeek::expected<ValPtr, std::string> JSON::Unserialize(util::byte_buffer_span buf, TypePtr type) {
    std::string text;
    std::transform(buf.begin(), buf.end(), std::back_inserter(text),
                   [](std::byte b) { return static_cast<std::string::value_type>(b); });

    auto semicolon = text.find(';');
    if ( semicolon == std::string::npos )
        return zeek::unexpected<std::string>("Version string missing");

    std::string_view version = std::string_view(text).substr(0, semicolon);
    if ( version != versioned_name )
        return zeek::unexpected<std::string>(
            util::fmt("Version doesn't match: %s vs %s", version.data(), versioned_name.c_str()));

    return zeek::detail::ValFromJSON(text.substr(semicolon + 1), type, Func::nil);
}

} // namespace zeek::storage::serializer::json
