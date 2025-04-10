// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

#include "zeek/3rdparty/nonstd/expected.hpp"

// These two types are not namespaced intentionally.
using zeek_int_t = int64_t;
using zeek_uint_t = uint64_t;

namespace zeek {

// Type aliases for nonstd::expected/nonstd::unexpected. These should be switched to use
// the std:: versions once we switch to C++20.
template<typename T, typename E>
using expected = nonstd::expected<T, E>;

template<typename E>
using unexpected = nonstd::unexpected<E>;

} // namespace zeek
