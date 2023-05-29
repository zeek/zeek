// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cassert>
#include <tuple>

#include <hilti/rt/types/port.h>

namespace zeek::spicy::rt {

/** A closed ranged of ports. */
struct PortRange {
    PortRange() = default;
    PortRange(hilti::rt::Port begin_, hilti::rt::Port end_) : begin(begin_), end(end_) {
        assert(begin.port() <= end.port());
        assert(begin.protocol() == end.protocol());
    }

    hilti::rt::Port begin; /**< first port in the range */
    hilti::rt::Port end;   /**< last port in the range */
};

inline bool operator==(const PortRange& a, const PortRange& b) {
    return std::tie(a.begin, a.end) == std::tie(b.begin, b.end);
}

inline bool operator!=(const PortRange& a, const PortRange& b) { return ! (a == b); }

inline PortRange make_port_range(hilti::rt::Port begin, hilti::rt::Port end) { return PortRange(begin, end); }

} // namespace zeek::spicy::rt
