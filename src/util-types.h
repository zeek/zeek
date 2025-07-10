// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <string>

#include "zeek/3rdparty/nonstd/expected.hpp"
#include "zeek/Span.h"

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

// Byte buffer types used by serialization code in storage and cluster.
using byte_buffer = std::vector<std::byte>;
using byte_buffer_span = Span<const std::byte>;

namespace util {
namespace detail {

/**
 * Wrapper class for functions like dirname(3) or basename(3) that won't
 * modify the path argument and may optionally abort execution on error.
 */
class SafePathOp {
public:
    std::string result;
    bool error = false;

protected:
    void CheckValid(const char* result, const char* path, bool error_aborts);
};

} // namespace detail

class SafeDirname : public detail::SafePathOp {
public:
    explicit SafeDirname(const char* path, bool error_aborts = true);
    explicit SafeDirname(const std::string& path, bool error_aborts = true);

private:
    void DoFunc(const std::string& path, bool error_aborts = true);
};

class SafeBasename : public detail::SafePathOp {
public:
    explicit SafeBasename(const char* path, bool error_aborts = true);
    explicit SafeBasename(const std::string& path, bool error_aborts = true);

private:
    void DoFunc(const std::string& path, bool error_aborts = true);
};

/**
 * Helper class that runs a function at destruction.
 */
class Deferred {
public:
    Deferred(std::function<void()> deferred) : deferred(std::move(deferred)) {}
    ~Deferred() { deferred(); }

private:
    std::function<void()> deferred;
};

} // namespace util
} // namespace zeek
