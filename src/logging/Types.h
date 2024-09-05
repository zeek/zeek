// See the file "COPYING" in the main distribution directory for copyright.
//
// Header for types shared between cluster and logging components.
//
// Currently these are in detail, but over time may move into zeek once
// the proper interfaces have been figured out.
#pragma once

#include <vector>

#include "zeek/threading/SerialTypes.h"

namespace zeek::logging::detail {

/**
 * A single log record.
 *
 * This is what a Zeek script Info record is rendered into.
 */
using LogRecord = std::vector<threading::Value>;

/**
 * A struct holding all ncessary information that relates to
 * log writes for a given path. These values are constant over
 * the lifetime of a \a WriterFrontend.
 */
struct LogWriteHeader {
    EnumValPtr stream_id;                 // The enum identifying the stream.
    EnumValPtr writer_id;                 // The enum identifying the writer for backwards compat.
    std::string filter_name;              // The name of the filter.
    std::string path;                     // The path as configured or produced by the filter's path_func.
    std::vector<threading::Field> fields; // The schema describing a log record.
};

/**
 * A batch of log records including their header.
 *
 * Log serializers produce instances when unserializing.
 *
 * This currently implies that the serializer process copies
 * into LogRecord / threading::Value structures. If the need
 * arises, there could be more abstractions to leverage
 * zero-copy approaches if the serialization format supports it
 * (capnproto or flatbuffers)
 */
struct LogWriteBatch {
    LogWriteHeader header;
    std::vector<LogRecord> records;
};

} // namespace zeek::logging::detail
