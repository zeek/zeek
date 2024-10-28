#include "Serializer.h"

#include <cstdint>

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/SerializationFormat.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/logging/Types.h"
#include "zeek/threading/SerialTypes.h"

using namespace zeek::cluster::detail;

// #define SERIALIZER_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#define SERIALIZER_DEBUG(...)                                                                                          \
    do {                                                                                                               \
    } while ( 0 )

bool BinarySerializationFormatLogSerializer::SerializeLogWriteInto(byte_buffer& buf,
                                                                   const logging::detail::LogWriteHeader& header,
                                                                   zeek::Span<logging::detail::LogRecord> records) {
    zeek::detail::BinarySerializationFormat fmt;

    SERIALIZER_DEBUG("Serializing stream=%s writer=%s filter=%s path=%s num_fields=%zu num_records=%zu\n", stream_id,
                     writer_id, header.filter_name.c_str(), header.path.c_str(), header.fields.size(), records.size());

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

std::optional<zeek::logging::detail::LogWriteBatch> BinarySerializationFormatLogSerializer::UnserializeLogWrite(
    const std::byte* buf, size_t size) {
    zeek::detail::BinarySerializationFormat fmt;
    fmt.StartRead(reinterpret_cast<const char*>(buf), size);

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

    SERIALIZER_DEBUG("stream=%s writer=%s filter=%s path=%s num_fields=%u num_records=%u\n", stream_id_str.c_str(),
                     writer_id_str.c_str(), header.filter_name.c_str(), header.path.c_str(), num_fields, num_records);

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
