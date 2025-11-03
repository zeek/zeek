// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/threading/Formatter.h"

namespace zeek::json::detail {
class NullDoubleWriter;
}

namespace zeek::threading::formatter {

/**
 * A thread-safe class for converting values into a JSON representation
 * and vice versa.
 */
class JSON : public Formatter {
public:
    enum TimeFormat : uint8_t {
        TS_EPOCH,          // Doubles that represents seconds from the UNIX epoch.
        TS_ISO8601,        // ISO 8601 defined human readable timestamp format.
        TS_MILLIS,         // Signed milliseconds from the UNIX epoch.  Some consumers need this (e.g.,
                           // elasticsearch).
        TS_MILLIS_UNSIGNED // Unsigned milliseconds from the UNIX epoch, overflowing.
    };

    JSON(MsgThread* t, TimeFormat tf, bool include_unset_fields = false);

    bool Describe(ODesc* desc, Value* val, const std::string& name = "") const override;
    bool Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const override;
    Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
                      TypeTag subtype = TYPE_ERROR) const override;

private:
    void BuildJSON(zeek::json::detail::NullDoubleWriter& writer, Value* val, const std::string& name = "") const;

    TimeFormat timestamps;
    bool include_unset_fields;
};

} // namespace zeek::threading::formatter
