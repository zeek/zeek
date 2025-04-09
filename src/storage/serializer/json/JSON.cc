// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/serializer/json/JSON.h"

#include "zeek/Func.h"

namespace zeek::storage::serializer::json {

std::unique_ptr<Serializer> JSON::Instantiate() { return std::make_unique<JSON>(); }

JSON::JSON() : Serializer("JSON") { versioned_name = util::fmt("%sv%d", name.c_str(), Val::JSON_VERSION); }

std::optional<util::byte_buffer> JSON::Serialize(ValPtr val, string_transform xform) {
    static auto byte_converter = [](u_char c) { return std::byte(c); };

    std::string version = versioned_name + ";";

    auto json = val->ToJSON();
    std::string_view json_str;

    util::byte_buffer buf;

    if ( ! xform ) {
        json_str = json->ToStdStringView();
        buf.reserve(json_str.size() + version.size());

        std::transform(version.begin(), version.end(), std::back_inserter(buf), byte_converter);
        std::transform(json_str.begin(), json_str.end(), std::back_inserter(buf), byte_converter);
    }
    else {
        std::string xformed;
        xformed = xform(version) + xform(json->ToStdStringView());
        std::transform(xformed.begin(), xformed.end(), std::back_inserter(buf), byte_converter);
    }

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
