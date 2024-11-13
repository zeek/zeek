// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/cluster/Serializer.h"

namespace zeek::cluster::detail {

// Implementation of the EventSerializer using the existing broker::detail::val_to_data()
// and broker::format::bin::v1::encode().
class BrokerBinV1_Serializer : public EventSerializer {
public:
    BrokerBinV1_Serializer() : EventSerializer("broker-bin-v1") {}

    bool SerializeEvent(detail::byte_buffer& buf, const detail::Event& event) override;

    std::optional<detail::Event> UnserializeEvent(detail::byte_buffer_span buf) override;
};

// Implementation of the EventSerializer that uses the existing broker::detail::val_to_data()
// and broker::format::json::v1::encode()
class BrokerJsonV1_Serializer : public EventSerializer {
public:
    BrokerJsonV1_Serializer() : EventSerializer("broker-json-v1") {}

    bool SerializeEvent(zeek::cluster::detail::byte_buffer& buf, const detail::Event& event) override;

    std::optional<detail::Event> UnserializeEvent(detail::byte_buffer_span buf) override;
};

} // namespace zeek::cluster::detail
