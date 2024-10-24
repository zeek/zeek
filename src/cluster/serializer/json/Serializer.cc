#include "Serializer.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Val.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Types.h"
#include "zeek/threading/MsgThread.h"
#include "zeek/threading/SerialTypes.h"
#include "zeek/threading/formatters/JSON.h"

using namespace zeek::cluster::detail;

namespace {

// Formatter wants a thread for error reporting and stuff.
//
// This is an absolute hack and likely will blow up! Should
// fix the formatter API instead.
class FakeThread : public threading::MsgThread {
public:
    FakeThread() {}

protected:
    bool OnHeartbeat(double network_time, double current_time) override { return true; }
    bool OnFinish(double network_time) override { return true; }
};

} // namespace

JSONLinesLogSerializer::JSONLinesLogSerializer() : cluster::LogSerializer("jsonlines-v1") {
    bool include_unset_fields = true; // Make configurable? How should this be configurable? At a cluster level?
    auto time_format = threading::formatter::JSON::TimeFormat::TS_EPOCH;

    msg_thread = std::make_unique<FakeThread>();
    msg_thread->Start(); // :-( We leak memory through heartbeats if we don't start the thread!
    formatter = std::make_unique<zeek::threading::formatter::JSON>(msg_thread.get(), time_format, include_unset_fields);
}

JSONLinesLogSerializer::~JSONLinesLogSerializer() = default;

bool JSONLinesLogSerializer::SerializeLogWriteInto(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                                   zeek::Span<logging::detail::LogRecord> records) {
    zeek::ODesc o;

    // Tricks to use the prio ** API.
    auto num_fields = static_cast<int>(header.fields.size());
    std::vector<const threading::Field*> fields;
    fields.resize(header.fields.size());
    for ( size_t i = 0; i < header.fields.size(); i++ )
        fields[i] = &header.fields[i];

    std::vector<threading::Value*> vals;
    vals.resize(header.fields.size());

    for ( auto& r : records ) {
        for ( size_t i = 0; i < r.size(); i++ )
            vals[i] = &r[i];

        formatter->Describe(&o, num_fields, fields.data(), vals.data());
        o.NL();
    }

    // Copy result. Would be nice if we could've rendered into byte_buffer
    // directly, but ODesc can't do that.
    buf.resize(o.Len());
    auto* b = o.TakeBytes();
    memcpy(buf.data(), b, buf.size());
    free(b);
    return true;
}

std::optional<logging::detail::LogWriteBatch> JSONLinesLogSerializer::UnserializeLogWrite(const std::byte* buf,
                                                                                          size_t size) {
    return std::nullopt;
}
