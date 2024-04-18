// See the file "COPYING" in the main distribution directory for copyright.
//
// The serializer for events to be sent around in a Zeek cluster. Yes, yet
// another serializer...

#pragma once

#include <optional>
#include <vector>


namespace zeek::cluster {

namespace detail {
class Event;

using byte_buffer = std::vector<std::byte>;
} // namespace detail


class Serializer {
public:
    virtual ~Serializer() = default;
    virtual bool SerializeEventInto(detail::byte_buffer& buf, const detail::Event& event) = 0;
    virtual std::optional<cluster::detail::Event> UnserializeEvent(const std::byte* payload, size_t payload_size) = 0;
};

} // namespace zeek::cluster
