#pragma once

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/logging/WriterFrontend.h"

namespace zeek::cluster::detail {

struct UnserializeLogWriteResult_ {
    logging::detail::LogWriteHeader header;
    std::vector<logging::detail::LogRecord> records;
};

using UnserializeLogWriteResult = std::optional<UnserializeLogWriteResult_>;

/**
 * A serializer interface for a batch of log records.
 *
 * TODO: Make this a pluggable component, also.
 */
class LogSerializer {
public:
    /**
     * Constructor.
     */
    explicit LogSerializer(std::string name) : name(std::move(name)){};

    virtual ~LogSerializer() = default;

    /**
     * Serialize all records into the given buffer.
     */
    virtual bool SerializeLogWriteInto(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                       zeek::Span<logging::detail::LogRecord> records) = 0;

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
    bool SerializeLogWriteInto(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                               zeek::Span<logging::detail::LogRecord> records) override;

    cluster::detail::UnserializeLogWriteResult UnserializeLogWrite(const std::byte* buf, size_t size) override;
};


} // namespace zeek::cluster::detail
