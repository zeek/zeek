// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/threading/formatters/JSON.h"

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define RAPIDJSON_HAS_STDSTRING 1

#include <rapidjson/internal/ieee754.h>
#include <cerrno>
#include <cmath>
#include <cstdint>

#include "zeek/Desc.h"
#include "zeek/threading/MsgThread.h"
#include "zeek/threading/formatters/detail/json.h"

namespace zeek::threading::formatter {

JSON::JSON(MsgThread* t, TimeFormat tf, bool arg_include_unset_fields)
    : Formatter(t), timestamps(tf), include_unset_fields(arg_include_unset_fields) {}

bool JSON::Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const {
    rapidjson::StringBuffer buffer;
    zeek::json::detail::NullDoubleWriter writer(buffer);

    writer.StartObject();

    for ( int i = 0; i < num_fields; i++ ) {
        if ( vals[i]->present || include_unset_fields )
            BuildJSON(writer, vals[i], fields[i]->name);
    }

    writer.EndObject();
    desc->Add(buffer.GetString());

    return true;
}

bool JSON::Describe(ODesc* desc, Value* val, const std::string& name) const {
    if ( desc->IsBinary() ) {
        GetThread()->Error("json formatter: binary format not supported");
        return false;
    }

    if ( (! val->present && ! include_unset_fields) || name.empty() )
        return true;

    rapidjson::Document doc;
    rapidjson::StringBuffer buffer;
    zeek::json::detail::NullDoubleWriter writer(buffer);

    writer.StartObject();
    BuildJSON(writer, val, name);
    writer.EndObject();

    desc->Add(buffer.GetString());
    return true;
}

Value* JSON::ParseValue(const std::string& s, const std::string& name, TypeTag type, TypeTag subtype) const {
    GetThread()->Error("JSON formatter does not support parsing yet.");
    return nullptr;
}

void JSON::BuildJSON(zeek::json::detail::NullDoubleWriter& writer, Value* val, const std::string& name) const {
    if ( ! name.empty() )
        writer.Key(name);

    if ( ! val->present ) {
        writer.Null();
        return;
    }

    switch ( val->type ) {
        case TYPE_BOOL: writer.Bool(val->val.int_val != 0); break;

        case TYPE_INT: writer.Int64(val->val.int_val); break;

        case TYPE_COUNT: writer.Uint64(val->val.uint_val); break;

        case TYPE_PORT: writer.Uint64(val->val.port_val.port); break;

        case TYPE_SUBNET: writer.String(Formatter::Render(val->val.subnet_val)); break;

        case TYPE_ADDR: writer.String(Formatter::Render(val->val.addr_val)); break;

        case TYPE_DOUBLE:
        case TYPE_INTERVAL: writer.Double(val->val.double_val); break;

        case TYPE_TIME: {
            if ( timestamps == TS_ISO8601 ) {
                char buffer[40];
                char buffer2[48];
                time_t the_time = time_t(floor(val->val.double_val));
                struct tm t;

                if ( ! gmtime_r(&the_time, &t) || ! strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &t) ) {
                    GetThread()->Error(
                        GetThread()->Fmt("json formatter: failure getting time: (%lf)", val->val.double_val));
                    // This was a failure, doesn't really matter what gets put here
                    // but it should probably stand out...
                    writer.String("2000-01-01T00:00:00.000000");
                }
                else {
                    double integ;
                    double frac = modf(val->val.double_val, &integ);

                    if ( frac < 0 )
                        frac += 1;

                    snprintf(buffer2, sizeof(buffer2), "%s.%06.0fZ", buffer, fabs(frac) * 1000000);
                    writer.String(buffer2, strlen(buffer2));
                }
            }

            else if ( timestamps == TS_EPOCH )
                writer.Double(val->val.double_val);

            else if ( timestamps == TS_MILLIS ) {
                // ElasticSearch uses milliseconds for timestamps
                writer.Int64((int64_t)(val->val.double_val * 1000));
            }
            else if ( timestamps == TS_MILLIS_UNSIGNED ) {
                // Without the cast through int64_t the resulting
                // uint64_t value is zero for negative timestamps
                // on arm64. This is UB territory, a negative value
                // cannot be represented in uint64_t and so the
                // compiler is free to do whatever. Prevent this by
                // casting through an int64_t.
                //
                // https://stackoverflow.com/a/55057221
                uint64_t v = static_cast<uint64_t>(static_cast<int64_t>(val->val.double_val * 1000));
                writer.Uint64(v);
            }

            break;
        }

        case TYPE_ENUM:
        case TYPE_STRING:
        case TYPE_FILE:
        case TYPE_FUNC: {
            writer.String(util::escape_utf8({val->val.string_val.data, static_cast<size_t>(val->val.string_val.length)},
                                            false, false));
            break;
        }

        case TYPE_TABLE: {
            writer.StartArray();

            for ( zeek_int_t idx = 0; idx < val->val.set_val.size; idx++ )
                BuildJSON(writer, val->val.set_val.vals[idx]);

            writer.EndArray();
            break;
        }

        case TYPE_VECTOR: {
            writer.StartArray();

            for ( zeek_int_t idx = 0; idx < val->val.vector_val.size; idx++ )
                BuildJSON(writer, val->val.vector_val.vals[idx]);

            writer.EndArray();
            break;
        }

        default: reporter->Warning("Unhandled type in JSON::BuildJSON"); break;
    }
}

} // namespace zeek::threading::formatter
