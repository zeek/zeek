// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <vector>

#include "zeek/cluster/Serializer.h"

namespace broker::zeek {
class Event;
}

namespace zeek {

class Type;
using TypePtr = zeek::IntrusivePtr<Type>;

namespace detail {
struct MetadataEntry;
}

using MetadataVector = std::vector<detail::MetadataEntry>;
using MetadataVectorPtr = std::unique_ptr<MetadataVector>;

namespace cluster::detail {

/**
 * Produce a MetadataVectorPtr from a broker event.
 *
 * The implementation relies on zeek::event_mgr.LookupMetadata()
 * to find the types of registered metadata. If there's no metadata
 * at all attached, returns a nullptr,
 *
 * @param ev The broker event.
 */
zeek::MetadataVectorPtr metadata_vector_from_broker_event(const broker::zeek::Event& ev);

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

} // namespace cluster::detail
} // namespace zeek
