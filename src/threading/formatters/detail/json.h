// See the file "COPYING" in the main distribution directory for copyright.

// Not installed - used by Val.cc and formatters/JSON.cc only.
#pragma once

#include <rapidjson/document.h>
#include <rapidjson/internal/ieee754.h>
#include <rapidjson/writer.h>

namespace zeek::json::detail {
// A rapidjson Writer that writes null for inf or nan numbers.
class NullDoubleWriter : public rapidjson::Writer<rapidjson::StringBuffer> {
public:
    explicit NullDoubleWriter(rapidjson::StringBuffer& stream) : rapidjson::Writer<rapidjson::StringBuffer>(stream) {}

    // This isn't defined as virtual in rapidjson's writer.h header, so we can't
    // define it as override.
    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    bool Double(double d) {
        if ( rapidjson::internal::Double(d).IsNanOrInf() )
            return rapidjson::Writer<rapidjson::StringBuffer>::Null();

        return rapidjson::Writer<rapidjson::StringBuffer>::Double(d);
    }
};

} // namespace zeek::json::detail
