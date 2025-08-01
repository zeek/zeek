// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <span>

namespace zeek {

template<class T>
using Span [[deprecated("Remove in v8.1: Use std::span instead")]] = std::span<T>;

} // namespace zeek
