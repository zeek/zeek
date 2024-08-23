#pragma once

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

#include "SerializationFormat.h"
#include "logging/WriterBackend.h"

namespace zeek::cluster::detail {

/**
 * How should we buffer and write?
 *
 * header, path
 * - record
 * - record
 * - record
 *
 * or

 * header,
 * - path, record
 * - path, record
 */


struct UnserializeLogWriteResult_ {
    cluster::detail::LogWriteHeader header;
    std::vector<logging::detail::LogRecord> records;
};

using UnserializeLogWriteResult = std::optional<UnserializeLogWriteResult_>;

/**
 * TODO: Make this a pluggable component in the future?
 */
class LogSerializer {
public:
    /**
     * Constructor.
     */
    explicit LogSerializer(std::string name) : name(std::move(name)){};

    /**
     * Serialize all records into the given buffer.
     */
    virtual bool SerializeLogWriteInto(byte_buffer& buf, const LogWriteHeader& header,
                                       cluster::detail::LogRecords records) = 0;

    /**
     * Unserialize log writes from a given buffer.
     *
     * Not sure this is so clever for cap-n-proto style protocols
     * where the underlying buffer shouldn't be freed.
     */
    virtual cluster::detail::UnserializeLogWriteResult UnserializeLogWrite(const std::byte* buf, size_t size) = 0;

    /**
     * Return the name of the serializer.
     */
    const std::string& Name() { return name; }

private:
    std::string name;
};

class BinarySerializationFormatLogSerializer : public LogSerializer {
public:
    BinarySerializationFormatLogSerializer() : LogSerializer("zeek-bin-serializer") {}
    bool SerializeLogWriteInto(byte_buffer& buf, const LogWriteHeader& header,
                               cluster::detail::LogRecords records) override;

    cluster::detail::UnserializeLogWriteResult UnserializeLogWrite(const std::byte* buf, size_t size) override;
};


} // namespace zeek::cluster::detail
