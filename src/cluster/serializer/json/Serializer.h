#pragma once

#include <memory>
#include <optional>

#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"

using namespace zeek;

namespace zeek {

namespace threading {
class Formatter;
class MsgThread;
} // namespace threading


namespace cluster::detail {

class JSONLinesLogSerializer : public cluster::LogSerializer {
public:
    JSONLinesLogSerializer();
    ~JSONLinesLogSerializer();
    bool SerializeLogWriteInto(cluster::detail::byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                               zeek::Span<logging::detail::LogRecord> records) override;

    std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(const std::byte* buf, size_t size) override;

private:
    std::unique_ptr<zeek::threading::MsgThread> msg_thread;
    std::unique_ptr<zeek::threading::Formatter> formatter;
};

} // namespace cluster::detail
} // namespace zeek
