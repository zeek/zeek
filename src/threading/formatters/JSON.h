// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#define RAPIDJSON_HAS_STDSTRING 1
// Remove in v7.1 when removing NullDoubleWriter below and also remove
// rapidjson include tweaks from  CMake's dynamic_plugin_base target.
#include <rapidjson/document.h>
#include <rapidjson/writer.h>

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
    enum TimeFormat {
        TS_EPOCH,   // Doubles that represents seconds from the UNIX epoch.
        TS_ISO8601, // ISO 8601 defined human readable timestamp format.
        TS_MILLIS   // Milliseconds from the UNIX epoch.  Some consumers need this (e.g.,
                    // elasticsearch).
    };

    JSON(MsgThread* t, TimeFormat tf, bool include_unset_fields = false);
    ~JSON() override = default;

    bool Describe(ODesc* desc, Value* val, const std::string& name = "") const override;
    bool Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const override;
    Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
                      TypeTag subtype = TYPE_ERROR) const override;

    class NullDoubleWriter : public rapidjson::Writer<rapidjson::StringBuffer> {
    public:
        [[deprecated("Remove in v7.1 - This is an implementation detail.")]] NullDoubleWriter(
            rapidjson::StringBuffer& stream);
        bool Double(double d);

    private:
        std::unique_ptr<json::detail::NullDoubleWriter> writer;
    };

private:
    void BuildJSON(zeek::json::detail::NullDoubleWriter& writer, Value* val, const std::string& name = "") const;

    TimeFormat timestamps;
    bool include_unset_fields;
};

} // namespace zeek::threading::formatter
