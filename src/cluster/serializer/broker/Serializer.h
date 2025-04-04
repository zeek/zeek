// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/cluster/Serializer.h"

namespace broker::zeek {
class Event;
}

namespace zeek::cluster::detail {

/**
 * Convert a broker::zeek::Event to cluster::detail::Event by looking
 * it up in Zeek's event handler registry and converting event arguments
 * to the appropriate Val instances.
 *
 * @param ev The broker side event.
 * @returns A zeek::cluster::detail::Event instance, or std::nullopt if the conversion failed.
 */
std::optional<detail::Event> to_zeek_event(const broker::zeek::Event& ev);

/**
 * Convert a cluster::detail::Event to a broker::zeek::Event.
 *
 * @param ev The cluster::detail::Event
 * @return A broker::zeek::Event to be serialized, or nullopt in case of errors.
 */
std::optional<broker::zeek::Event> to_broker_event(const detail::Event& ev);

// Implementation of the EventSerializer using the existing broker::detail::val_to_data()
// and broker::format::bin::v1::encode().
class BrokerBinV1_Serializer : public EventSerializer {
public:
    BrokerBinV1_Serializer() : EventSerializer("broker-bin-v1") {}

    bool SerializeEvent(byte_buffer& buf, const detail::Event& event) override;

    std::optional<detail::Event> UnserializeEvent(byte_buffer_span buf) override;
};

// Implementation of the EventSerializer that uses the existing broker::detail::val_to_data()
// and broker::format::json::v1::encode()
class BrokerJsonV1_Serializer : public EventSerializer {
public:
    BrokerJsonV1_Serializer() : EventSerializer("broker-json-v1") {}

    bool SerializeEvent(byte_buffer& buf, const detail::Event& event) override;

    std::optional<detail::Event> UnserializeEvent(byte_buffer_span buf) override;
};

} // namespace zeek::cluster::detail
