// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <span>
#include <string>

#include "zeek/IntrusivePtr.h"
#include "zeek/net_util.h"

// Helpers for cluster.bif

namespace zeek {

namespace detail {
class Frame;
}

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;

class Val;
using ValPtr = IntrusivePtr<Val>;
using ArgsSpan = std::span<const ValPtr>;

namespace cluster::detail::bif {

/**
 * Cluster::make_event() implementation.
 *
 * @param topic The topic to publish to. Should be a StringVal.
 * @param args The arguments to the BiF function. May either be a prepared event from make_event(),
 *  or a FuncValPtr and it's arguments
 *
 * @return A RecordValPtr representing a Cluster::Event record instance.
 */
zeek::RecordValPtr make_event(zeek::ArgsSpan args);

/**
 * Publish helper.
 *
 * @param topic The topic to publish to. Should be a StringVal.
 * @param args The arguments to the BiF function. May either be a prepared event from make_event(),
 *  or a FuncValPtr and it's arguments
 *
 * @return A BoolValPtr that's true if the event was published, else false.
 */
zeek::ValPtr publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args);

bool is_cluster_pool(const zeek::Val* pool);

/**
 * Create a Cluster::EndpointInfo record with a nested Cluster::NetworkInfo record.
 *
 * @param id The string to use as id in the record.
 * @param address The string to use as address in the network record.
 * @param port The port to use in the network record.
 * @param proto The proto for the given port value.
 *
 * @returns A record value of type Cluster::EndpointInfo filled with the provided info.
 */
zeek::RecordValPtr make_endpoint_info(const std::string& id, const std::string& address, uint32_t port,
                                      TransportProto proto, std::optional<std::string> application_name);

/**
 * Helper to go from a vector or array of std::strings to a zeek::VectorVal.
 *
 * @param strings The std::string instances.
 *
 * @return a VectorVal instance of type string_vec filled with strings.
 */
zeek::VectorValPtr make_string_vec(std::span<const std::string> strings);

} // namespace cluster::detail::bif

} // namespace zeek
