// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <span>

#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"

namespace zeek::cluster::detail {

class BinarySerializationFormatLogSerializer : public cluster::LogSerializer {
public:
    BinarySerializationFormatLogSerializer() : LogSerializer("zeek-bin-serializer") {}

    bool SerializeLogWrite(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                           std::span<logging::detail::LogRecord> records) override;

    std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(byte_buffer_span buf) override;
};

} // namespace zeek::cluster::detail
