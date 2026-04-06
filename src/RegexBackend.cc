// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RegexBackend.h"

#include <algorithm>

#include "rust/corrosion_generated/cbindgen/zeek_regex_backend/include/zeek_regex_backend.h"

namespace zeek::detail {

static std::string take_rust_regex_string(char* text) {
    if ( ! text )
        return {};

    std::string result = text;
    zeek_rust_regex_string_free(text);
    return result;
}

void RustRegexMatcherDeleter::operator()(ZeekRustRegexMatcher* matcher) const { zeek_rust_regex_matcher_free(matcher); }

void RustRegexSetMatcherDeleter::operator()(ZeekRustRegexSetMatcher* matcher) const {
    zeek_rust_regex_set_matcher_free(matcher);
}

void RustRegexStreamMatcherDeleter::operator()(ZeekRustRegexStreamMatcher* matcher) const {
    zeek_rust_regex_stream_matcher_free(matcher);
}

void RustRegexStreamStateDeleter::operator()(ZeekRustRegexStreamState* state) const {
    zeek_rust_regex_stream_state_free(state);
}

uint32_t RustRegexBackendAbiVersion() { return zeek_rust_regex_backend_abi_version(); }

uint32_t RustRegexBackendSmokeTest() { return zeek_rust_regex_backend_smoke_test(); }

bool RustRegexBackendAvailable() {
    return RustRegexBackendAbiVersion() == ZEEK_RUST_REGEX_BACKEND_ABI_VERSION &&
           RustRegexBackendSmokeTest() == ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN;
}

bool NormalizeZeekPatternForRust(const char* pattern, std::string* normalized) {
    if ( ! pattern || ! normalized )
        return false;

    auto* rust_text = zeek_rust_regex_compat_normalize_pattern(pattern);

    if ( ! rust_text )
        return false;

    *normalized = take_rust_regex_string(rust_text);
    return true;
}

std::string DeriveRustPatternFromExact(const char* exact) {
    if ( ! exact )
        return {};

    return take_rust_regex_string(zeek_rust_regex_compat_derive_rust_pattern_from_exact(exact));
}

std::string DeriveAnywherePatternFromExact(const char* exact) {
    if ( ! exact )
        return {};

    return take_rust_regex_string(zeek_rust_regex_compat_derive_anywhere_pattern_from_exact(exact));
}

RustRegexMatcherHandle CompileRustRegexMatcher(const std::string& pattern) {
    if ( pattern.empty() )
        return {};

    return RustRegexMatcherHandle{zeek_rust_regex_matcher_compile(pattern.c_str())};
}

RustRegexMatcherHandle CompileRustRegexMatcherFromExact(const std::string& exact_pattern) {
    if ( exact_pattern.empty() )
        return {};

    return RustRegexMatcherHandle{zeek_rust_regex_matcher_compile_from_zeek_exact(exact_pattern.c_str())};
}

bool RustRegexMatcherMatchAll(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len) {
    return matcher && zeek_rust_regex_matcher_match_all(matcher.get(), data, len) != 0;
}

int RustRegexMatcherFindEnd(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len) {
    return matcher ? zeek_rust_regex_matcher_find_end(matcher.get(), data, len) : 0;
}

int RustRegexMatcherLongestPrefix(const RustRegexMatcherHandle& matcher, const uint8_t* data, size_t len, bool bol,
                                  bool eol) {
    return matcher ? zeek_rust_regex_matcher_longest_prefix(matcher.get(), data, len, bol, eol) : -1;
}

RustRegexSetMatcherHandle CompileRustRegexSetMatcher(const std::vector<const char*>& patterns,
                                                     const std::vector<std::intptr_t>& ids) {
    if ( patterns.empty() || patterns.size() != ids.size() )
        return {};

    return RustRegexSetMatcherHandle{zeek_rust_regex_set_matcher_compile(patterns.data(), ids.data(), patterns.size())};
}

RustRegexSetMatcherHandle CompileRustRegexSetMatcherFromExact(const std::vector<const char*>& exact_patterns,
                                                              const std::vector<std::intptr_t>& ids) {
    if ( exact_patterns.empty() || exact_patterns.size() != ids.size() )
        return {};

    return RustRegexSetMatcherHandle{
        zeek_rust_regex_set_matcher_compile_from_zeek_exact(exact_patterns.data(), ids.data(), exact_patterns.size())};
}

bool RustRegexSetMatcherMatchAny(const RustRegexSetMatcherHandle& matcher, const uint8_t* data, size_t len) {
    return matcher && zeek_rust_regex_set_matcher_matches(matcher.get(), data, len, nullptr, 0) != 0;
}

size_t RustRegexSetMatcherPatternLen(const RustRegexSetMatcherHandle& matcher) {
    return matcher ? zeek_rust_regex_set_matcher_pattern_len(matcher.get()) : 0;
}

void RustRegexSetMatcherAppendMatches(const RustRegexSetMatcherHandle& matcher, const uint8_t* data, size_t len,
                                      std::vector<int>& matches) {
    if ( ! matcher )
        return;

    const auto count = zeek_rust_regex_set_matcher_pattern_len(matcher.get());

    if ( count == 0 )
        return;

    std::vector<std::intptr_t> ids(count);
    const auto matched = zeek_rust_regex_set_matcher_matches(matcher.get(), data, len, ids.data(), ids.size());

    for ( size_t i = 0; i < std::min(matched, ids.size()); ++i )
        matches.push_back(static_cast<int>(ids[i]));
}

RustRegexStreamMatcherHandle CompileRustRegexStreamMatcher(const std::vector<const char*>& patterns,
                                                           const std::vector<std::intptr_t>& ids,
                                                           bool dot_matches_new_line, size_t cache_capacity) {
    if ( patterns.empty() || patterns.size() != ids.size() )
        return {};

    return RustRegexStreamMatcherHandle{zeek_rust_regex_stream_matcher_compile(patterns.data(), ids.data(),
                                                                               patterns.size(), dot_matches_new_line,
                                                                               cache_capacity)};
}

RustRegexStreamMatcherHandle CompileRustRegexStreamMatcherFromZeek(const std::vector<const char*>& patterns,
                                                                   const std::vector<std::intptr_t>& ids,
                                                                   bool dot_matches_new_line, size_t cache_capacity) {
    if ( patterns.empty() || patterns.size() != ids.size() )
        return {};

    return RustRegexStreamMatcherHandle{
        zeek_rust_regex_stream_matcher_compile_from_zeek(patterns.data(), ids.data(), patterns.size(),
                                                         dot_matches_new_line, cache_capacity)};
}

size_t RustRegexStreamMatcherPatternLen(const RustRegexStreamMatcherHandle& matcher) {
    return matcher ? zeek_rust_regex_stream_matcher_pattern_len(matcher.get()) : 0;
}

size_t RustRegexStreamMatcherCacheBytes(const RustRegexStreamMatcherHandle& matcher) {
    return matcher ? zeek_rust_regex_stream_matcher_cache_bytes(matcher.get()) : 0;
}

size_t RustRegexStreamMatcherCacheClears(const RustRegexStreamMatcherHandle& matcher) {
    return matcher ? zeek_rust_regex_stream_matcher_cache_clears(matcher.get()) : 0;
}

RustRegexStreamStateHandle CreateRustRegexStreamState(const RustRegexStreamMatcherHandle& matcher) {
    return matcher ? RustRegexStreamStateHandle{zeek_rust_regex_stream_state_create(matcher.get())} :
                     RustRegexStreamStateHandle{};
}

void RustRegexStreamStateAppendMatches(const RustRegexStreamMatcherHandle& matcher, RustRegexStreamStateHandle& state,
                                       const uint8_t* data, size_t len, bool bol, bool eol,
                                       bool suppress_initial_empty_visible_match,
                                       std::vector<std::pair<int, uint64_t>>& matches) {
    if ( ! matcher || ! state )
        return;

    const auto count = zeek_rust_regex_stream_matcher_pattern_len(matcher.get());

    if ( count == 0 )
        return;

    std::vector<std::intptr_t> ids(count);
    std::vector<uint64_t> positions(count);
    const auto matched = zeek_rust_regex_stream_state_match(matcher.get(), state.get(), data, len, bol, eol,
                                                            suppress_initial_empty_visible_match, ids.data(),
                                                            positions.data(), ids.size());

    for ( size_t i = 0; i < std::min({matched, ids.size(), positions.size()}); ++i )
        matches.emplace_back(static_cast<int>(ids[i]), positions[i]);
}

} // namespace zeek::detail
