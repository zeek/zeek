// See the file "COPYING" in the main distribution directory for copyright.

// Header for types shared between cluster and logging components.
//
// Currently these are in detail, but over time may move into the
// public namespace once established.

#pragma once

#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek {
class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;

namespace logging::detail {

/**
 * A single log record.
 *
 * This is what a Zeek record value passed into Log::write()
 * is converted into before passed to a local log writer or
 * send via the cluster to a remote node.
 */
using LogRecord = std::vector<threading::Value>;

/**
 * A struct holding all necessary information that relates to
 * log writes for a given path. These values are constant over
 * the lifetime of a \a WriterFrontend.
 *
 * Note that the constructor, destructor and assignment operator are
 * defaulted in Types.cc. This is to avoid a Val.h include here.
 */
struct LogWriteHeader {
    /**
     * Default constructor.
     */
    LogWriteHeader() = default;

    /**
     * Constructor that populates stream_name and writer_name.
     *
     * @param stream_id Enum value representing the stream.
     * @param writer_id Enum value representing the writer.
     * @param filter_name The filter name of the writer frontend.
     * @param path The path of the writer frontend.
     */
    LogWriteHeader(EnumValPtr stream_id, EnumValPtr writer_id, std::string filter_name, std::string path);

    /**
     * Assignment operator.
     */
    LogWriteHeader& operator=(const LogWriteHeader& other) = default;

    /**
     * Destructor.
     */
    ~LogWriteHeader() = default;

    /**
     * Copy constructor.
     */
    LogWriteHeader(const LogWriteHeader& other) = default;

    /**
     * Move constructor.
     */
    LogWriteHeader(LogWriteHeader&& other) noexcept = default;

    /**
     * Helper to populate stream_id and writer_id after the
     * stream_name and writer_name members were set.
     *
     * @return true if matching enum values were, else false.
     */
    bool PopulateEnumVals();

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
 * This is the object created when unserialzing a log-write
 * from another cluster node.
 *
 * This layout currently implies that during de-serialization
 * data is copied into LogRecord / threading::Value structures.
 * If the need for zero-copy approaches arises, might need a
 * different approach to free the underlying buffer (capnproto).
 */
struct LogWriteBatch {
    LogWriteHeader header;
    std::vector<LogRecord> records;
};

} // namespace logging::detail
} // namespace zeek
