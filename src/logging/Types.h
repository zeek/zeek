// See the file "COPYING" in the main distribution directory for copyright.
//
// Header for types shared between cluster and logging components.
//
// Currently these are in detail, but over time may move into the
// public namespace once established.

#pragma once

#include <vector>

#include "zeek/threading/SerialTypes.h"

namespace zeek::logging::detail {

/**
 * A single log record.
 *
 * This is what a Zeek record value passed into Log::write()
 * is rendered into before passed to a local log writer or
 * sent via the cluster to a remote node.
 */
using LogRecord = std::vector<threading::Value>;

/**
 * A struct holding all ncessary information that relates to
 * log writes for a given path. These values are constant over
 * the lifetime of a \a WriterFrontend.
 */
struct LogWriteHeader {
    EnumValPtr stream_id;                 // The enum identifying the stream.
    std::string stream_name;              // The name of the stream, e.g. Conn::LOG
    EnumValPtr writer_id;                 // The enum identifying the writer. Mostly for backwards compat with broker.
    std::string writer_name;              // The name of the writer, e.g. WRITER_ASCII.
    std::string filter_name;              // The name of the filter.
    std::string path;                     // The path as configured or produced by the filter's path_func.
    std::vector<threading::Field> fields; // The schema describing a log record.
};

/**
 * A batch of log records including their header.
 *
 * This is the object created when unserialziing a log-write
 * message sent between nodes.
 *
 * This currently implies that the serializer process copies
 * into LogRecord / threading::Value structures. If the need
 * for zero-copy approaches arises, might need a different
 * approach to free the underlying buffer. Think capnproto or
 * flatbuffers.
 */
struct LogWriteBatch {
    LogWriteHeader header;
    std::vector<LogRecord> records;
};

} // namespace zeek::logging::detail
