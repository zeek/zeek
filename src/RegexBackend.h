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

void zeek_rust_regex_matcher_free(ZeekRustRegexMatcher* matcher);
void zeek_rust_regex_set_matcher_free(ZeekRustRegexSetMatcher* matcher);
void zeek_rust_regex_stream_matcher_free(ZeekRustRegexStreamMatcher* matcher);
void zeek_rust_regex_stream_state_free(ZeekRustRegexStreamState* state);
}

namespace zeek::detail {

// RAII wrapper around backend types.
template<typename T, void (*free_t)(T*)>
struct RAII : std::unique_ptr<T, decltype(free_t)> {
    RAII(T* value = nullptr) : std::unique_ptr<T, decltype(free_t)>(value, free_t) {}
};

using RustRegexMatcherHandle = RAII<ZeekRustRegexMatcher, zeek_rust_regex_matcher_free>;
using RustRegexSetMatcherHandle = RAII<ZeekRustRegexSetMatcher, zeek_rust_regex_set_matcher_free>;
using RustRegexStreamMatcherHandle = RAII<ZeekRustRegexStreamMatcher, zeek_rust_regex_stream_matcher_free>;
using RustRegexStreamStateHandle = RAII<ZeekRustRegexStreamState, zeek_rust_regex_stream_state_free>;

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
