#pragma once

#include <optional>

#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"

using namespace zeek;

namespace zeek::cluster::detail {

class BinarySerializationFormatLogSerializer : public cluster::LogSerializer {
public:
    BinarySerializationFormatLogSerializer() : LogSerializer("zeek-bin-serializer") {}
    bool SerializeLogWriteInto(cluster::detail::byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                               zeek::Span<logging::detail::LogRecord> records) override;

    std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(const std::byte* buf, size_t size) override;
};

} // namespace zeek::cluster::detail
