// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/Span.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::cluster::nats {

namespace detail {

class NATSManagerImpl;

}

class NATSBackend : public cluster::Backend {
public:
    NATSBackend(EventSerializer* event_serializer, LogSerializer* log_serializer);
    ~NATSBackend();

    void InitPostScript() override;
    void Terminate() override;

    bool Connect();

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) override;

    bool Subscribe(const std::string& topic_prefix) override;

    bool Unsubscribe(const std::string& topic_prefix) override;

    bool PublishLogWrites(const logging::detail::LogWriteHeader& header,
                          zeek::Span<logging::detail::LogRecord> records) override;

    static Backend* Instantiate(EventSerializer* event_serializer, LogSerializer* log_serializer) {
        return new NATSBackend(event_serializer, log_serializer);
    }

private:
    std::unique_ptr<nats::detail::NATSManagerImpl> impl;
};

} // namespace zeek::cluster::nats
