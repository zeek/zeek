// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/serializer/binary-serialization-format/Serializer.h"

#include <cstdint>

#include "zeek/DebugLogger.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/SerializationFormat.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/cluster/serializer/binary-serialization-format/Plugin.h"
#include "zeek/logging/Types.h"
#include "zeek/threading/SerialTypes.h"

using namespace zeek::cluster;

namespace zeek::plugin::Zeek_Binary_Serializer {

extern Plugin plugin;

}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SERIALIZER_DEBUG(...) PLUGIN_DBG_LOG(zeek::plugin::Zeek_Binary_Serializer::plugin, __VA_ARGS__)

bool detail::BinarySerializationFormatLogSerializer::SerializeLogWrite(byte_buffer& buf,
                                                                       const logging::detail::LogWriteHeader& header,
                                                                       zeek::Span<logging::detail::LogRecord> records) {
    zeek::detail::BinarySerializationFormat fmt;

    SERIALIZER_DEBUG("Serializing stream=%s writer=%s filter=%s path=%s num_fields=%zu num_records=%zu",
                     header.stream_name.c_str(), header.filter_name.c_str(), header.filter_name.c_str(),
                     header.path.c_str(), header.fields.size(), records.size());

    fmt.StartWrite();

    // Header: stream_name, writer_id, filter_name, path, num_fields, schema fields
    bool success = true;
    success &= fmt.Write(header.stream_name, "stream_id");
    success &= fmt.Write(header.writer_name, "writer_id");
    success &= fmt.Write(header.filter_name, "filter_name");
    success &= fmt.Write(header.path, "path");
    success &= fmt.Write(static_cast<uint32_t>(header.fields.size()), "num_fields");
    for ( const auto& f : header.fields )
        success &= f.Write(&fmt);

    success &= fmt.Write(static_cast<uint32_t>(records.size()), "num_records");

    if ( ! success ) {
        reporter->Error("Failed to remotely log stream %s: header serialization failed", header.stream_name.c_str());
        return false;
    }

    // Write out the payload.
    for ( const auto& rec : records ) {
        for ( size_t i = 0; i < rec.size(); ++i ) {
            if ( ! rec[i].Write(&fmt) ) {
                reporter->Error("Failed to remotely log stream %s: field %zu serialization failed",
                                header.stream_name.c_str(), i);
                return false;
            }
        }
    }

    char* data;
    uint32_t len;
    len = fmt.EndWrite(&data);

    // Copy result into buffer. Would be nice to serialize directly into the buffer,
    // but the SerializationFormat doesn't really allow for that.
    buf.resize(len);
    memcpy(buf.data(), data, len);
    free(data);
    return true;
}

std::optional<zeek::logging::detail::LogWriteBatch> detail::BinarySerializationFormatLogSerializer::UnserializeLogWrite(
    byte_buffer_span buf) {
    zeek::detail::BinarySerializationFormat fmt;
    fmt.StartRead(reinterpret_cast<const char*>(buf.data()), buf.size());

    logging::detail::LogWriteHeader header;
    std::vector<logging::detail::LogRecord> records;

    fmt.Read(&header.stream_name, "stream_id");
    fmt.Read(&header.writer_name, "writer_id");
    fmt.Read(&header.filter_name, "filter_name");
    fmt.Read(&header.path, "path");

    if ( ! header.PopulateEnumVals() ) {
        reporter->Error("Failed to populate enum vals from stream_name='%s' writer_name='%s'",
                        header.stream_name.c_str(), header.writer_name.c_str());
        return {};
    };

    uint32_t num_fields;
    if ( ! fmt.Read(&num_fields, "num_fields") ) {
        reporter->Error("Failed to read num_fields");
        return {};
    }

    header.fields.resize(num_fields);

    for ( size_t i = 0; i < header.fields.size(); i++ )
        if ( ! header.fields[i].Read(&fmt) ) {
            reporter->Error("Failed to read schema field %zu", i);
            return {};
        }

    uint32_t num_records;
    if ( ! fmt.Read(&num_records, "num_records") ) {
        reporter->Error("Failed to read schema field");
        return {};
    }

    SERIALIZER_DEBUG("stream=%s writer=%s filter=%s path=%s num_fields=%u num_records=%u", header.stream_name.c_str(),
                     header.writer_name.c_str(), header.filter_name.c_str(), header.path.c_str(), num_fields,
                     num_records);

    records.reserve(num_records);

    for ( uint32_t i = 0; i < num_records; i++ ) {
        logging::detail::LogRecord rec(num_fields);
        for ( uint32_t j = 0; j < num_fields; j++ ) {
            if ( ! rec[j].Read(&fmt) ) {
                reporter->Error("Failed to read record %u field %u", i, j);
                return {};
            }
        }

        records.push_back(std::move(rec));
    }

    fmt.EndRead();

    return logging::detail::LogWriteBatch{std::move(header), std::move(records)};
}

#include "zeek/ID.h"

#include "zeek/3rdparty/doctest.h"

TEST_SUITE_BEGIN("cluster serializer binary-serialization-format");

TEST_CASE("roundtrip") {
    zeek::byte_buffer buf;
    detail::BinarySerializationFormatLogSerializer serializer;

    static const auto& stream_id_type = zeek::id::find_type<zeek::EnumType>("Log::ID");
    static const auto& writer_id_type = zeek::id::find_type<zeek::EnumType>("Log::Writer");

    unsigned char expected_bytes[] = {0x00, 0x00, 0x00, 0x0c, 0x4c, 0x6f, 0x67, 0x3a, 0x3a, 0x55, 0x4e, 0x4b, 0x4e,
                                      0x4f, 0x57, 0x4e, 0x00, 0x00, 0x00, 0x10, 0x4c, 0x6f, 0x67, 0x3a, 0x3a, 0x57,
                                      0x52, 0x49, 0x54, 0x45, 0x52, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x00, 0x00, 0x00,
                                      0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00, 0x00, 0x07, 0x6d,
                                      0x79, 0x2d, 0x70, 0x61, 0x74, 0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x00, 0x02, 0x74, 0x73, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x16, 0x00,
                                      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x16, 0x01,
                                      0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
                                      0x00, 0x00, 0x16, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::byte* p = reinterpret_cast<std::byte*>(&expected_bytes[0]);
    zeek::byte_buffer expected{p, p + sizeof(expected_bytes)};

    auto s = stream_id_type->Lookup("Log::UNKNOWN");
    REQUIRE_GE(s, 0);
    auto w = writer_id_type->Lookup("Log::WRITER_NONE");
    REQUIRE_GE(w, 0);

    const auto& stream = stream_id_type->GetEnumVal(s);
    const auto& writer = writer_id_type->GetEnumVal(w);

    zeek::logging::detail::LogWriteHeader hdr(stream, writer, "default", "my-path");
    hdr.fields = {zeek::threading::Field{"ts", nullptr, zeek::TYPE_TIME, zeek::TYPE_ERROR, false}};

    std::vector<zeek::logging::detail::LogRecord> records;
    records.push_back({zeek::threading::Value{zeek::TYPE_TIME, zeek::TYPE_ERROR, true}});
    records.push_back({zeek::threading::Value{zeek::TYPE_TIME, zeek::TYPE_ERROR, true}});
    records[0][0].val.double_val = 1.0;
    records[1][0].val.double_val = 2.0;

    REQUIRE(serializer.SerializeLogWrite(buf, hdr, records));
    CHECK_EQ(expected, buf);

    // for ( auto c : buf )
    //    std::fprintf(stderr, "0x%02x,", int(c));


    auto result = serializer.UnserializeLogWrite(buf);
    REQUIRE(result);

    CHECK_EQ(result->header.fields.size(), 1);
    CHECK_EQ(result->records.size(), 2);
    CHECK_EQ(result->records[0][0].val.double_val, 1.0);
    CHECK_EQ(result->records[1][0].val.double_val, 2.0);
    CHECK_EQ("Log::UNKNOWN", result->header.stream_name);
    CHECK_EQ("Log::WRITER_NONE", result->header.writer_name);
}
TEST_SUITE_END();
