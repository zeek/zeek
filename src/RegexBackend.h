// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" {
struct ZeekRustRegexMatcher;
struct ZeekRustRegexSetMatcher;
struct ZeekRustRegexStreamMatcher;
struct ZeekRustRegexStreamState;
}

namespace zeek::detail {

struct RustRegexMatcherDeleter {
    void operator()(ZeekRustRegexMatcher* matcher) const;
};

struct RustRegexSetMatcherDeleter {
    void operator()(ZeekRustRegexSetMatcher* matcher) const;
};

struct RustRegexStreamMatcherDeleter {
    void operator()(ZeekRustRegexStreamMatcher* matcher) const;
};

struct RustRegexStreamStateDeleter {
    void operator()(ZeekRustRegexStreamState* state) const;
};

using RustRegexMatcherHandle = std::unique_ptr<ZeekRustRegexMatcher, RustRegexMatcherDeleter>;
using RustRegexSetMatcherHandle = std::unique_ptr<ZeekRustRegexSetMatcher, RustRegexSetMatcherDeleter>;
using RustRegexStreamMatcherHandle = std::unique_ptr<ZeekRustRegexStreamMatcher, RustRegexStreamMatcherDeleter>;
using RustRegexStreamStateHandle = std::unique_ptr<ZeekRustRegexStreamState, RustRegexStreamStateDeleter>;

uint32_t RustRegexBackendAbiVersion();
uint32_t RustRegexBackendSmokeTest();
bool RustRegexBackendAvailable();
bool NormalizeZeekPatternForRust(const char* pattern, std::string* normalized);
std::string DeriveRustPatternFromExact(const char* exact);
std::string DeriveAnywherePatternFromExact(const char* exact);
RustRegexMatcherHandle CompileRustRegexMatcher(const std::string& pattern);
RustRegexMatcherHandle CompileRustRegexMatcherFromExact(const std::string& exact_pattern);
bool RustRegexMatcherMatchAll(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len);
int RustRegexMatcherFindEnd(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len);
int RustRegexMatcherLongestPrefix(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len, bool bol,
                                  bool eol);
RustRegexSetMatcherHandle CompileRustRegexSetMatcher(const std::vector<const char*>& patterns,
                                                     const std::vector<std::intptr_t>& ids);
RustRegexSetMatcherHandle CompileRustRegexSetMatcherFromExact(const std::vector<const char*>& exact_patterns,
                                                              const std::vector<std::intptr_t>& ids);
bool RustRegexSetMatcherMatchAny(const RustRegexSetMatcherHandle& matcher, const uint8_t* data, size_t len);
size_t RustRegexSetMatcherPatternLen(const RustRegexSetMatcherHandle& matcher);
void RustRegexSetMatcherAppendMatches(const RustRegexSetMatcherHandle& matcher, const uint8_t* data, size_t len,
                                      std::vector<int>& matches);
RustRegexStreamMatcherHandle CompileRustRegexStreamMatcher(const std::vector<const char*>& patterns,
                                                           const std::vector<std::intptr_t>& ids,
                                                           bool dot_matches_new_line, size_t cache_capacity);
RustRegexStreamMatcherHandle CompileRustRegexStreamMatcherFromZeek(const std::vector<const char*>& patterns,
                                                                   const std::vector<std::intptr_t>& ids,
                                                                   bool dot_matches_new_line, size_t cache_capacity);
size_t RustRegexStreamMatcherPatternLen(const RustRegexStreamMatcherHandle& matcher);
size_t RustRegexStreamMatcherCacheBytes(const RustRegexStreamMatcherHandle& matcher);
size_t RustRegexStreamMatcherCacheClears(const RustRegexStreamMatcherHandle& matcher);
RustRegexStreamStateHandle CreateRustRegexStreamState(const RustRegexStreamMatcherHandle& matcher);
void RustRegexStreamStateAppendMatches(const RustRegexStreamMatcherHandle& matcher, RustRegexStreamStateHandle& state,
                                       const uint8_t* data, size_t len, bool bol, bool eol,
                                       bool suppress_initial_empty_visible_match,
                                       std::vector<std::pair<int, uint64_t>>& matches);

} // namespace zeek::detail
