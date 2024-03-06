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
    NATSBackend(Serializer* serializer);
    ~NATSBackend();

    void InitPostScript() override;
    void Terminate() override;

    bool Connect();

    bool PublishEvent(const std::string& topic, const cluster::detail::Event& event) override;

    bool Subscribe(const std::string& topic_prefix) override;

    bool Unsubscribe(const std::string& topic_prefix) override;

    bool PublishLogWrites(const logging::detail::LogWriteHeader& header,
                          zeek::Span<logging::detail::LogRecord> records) override;

    static Backend* Instantiate(Serializer* serializer) { return new NATSBackend(serializer); }

private:
    std::unique_ptr<nats::detail::NATSManagerImpl> impl;
};

} // namespace zeek::cluster::nats
