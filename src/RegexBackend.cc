// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/RegexBackend.h"

#include <algorithm>

namespace zeek::detail {

uint32_t RustRegexBackendAbiVersion() { return zeek_rust_regex_backend_abi_version(); }

uint32_t RustRegexBackendSmokeTest() { return zeek_rust_regex_backend_smoke_test(); }

bool RustRegexBackendAvailable() {
    return RustRegexBackendAbiVersion() == ZEEK_RUST_REGEX_BACKEND_ABI_VERSION &&
           RustRegexBackendSmokeTest() == ZEEK_RUST_REGEX_BACKEND_SMOKE_TEST_TOKEN;
}

void* CompileRustRegexMatcher(const std::string& pattern) {
    if ( pattern.empty() )
        return nullptr;

    return zeek_rust_regex_matcher_compile(pattern.c_str());
}

void FreeRustRegexMatcher(void* matcher) {
    zeek_rust_regex_matcher_free(reinterpret_cast<ZeekRustRegexMatcher*>(matcher));
}

bool RustRegexMatcherMatchAll(const void* matcher, const uint8_t* data, size_t len) {
    return zeek_rust_regex_matcher_match_all(reinterpret_cast<const ZeekRustRegexMatcher*>(matcher), data, len) != 0;
}

int RustRegexMatcherFindEnd(const void* matcher, const uint8_t* data, size_t len) {
    return zeek_rust_regex_matcher_find_end(reinterpret_cast<const ZeekRustRegexMatcher*>(matcher), data, len);
}

int RustRegexMatcherLongestPrefix(const void* matcher, const uint8_t* data, size_t len, bool bol, bool eol) {
    return zeek_rust_regex_matcher_longest_prefix(reinterpret_cast<const ZeekRustRegexMatcher*>(matcher), data, len,
                                                  bol, eol);
}

void* CompileRustRegexSetMatcher(const std::vector<const char*>& patterns, const std::vector<std::intptr_t>& ids) {
    if ( patterns.empty() || patterns.size() != ids.size() )
        return nullptr;

    return zeek_rust_regex_set_matcher_compile(patterns.data(), ids.data(), patterns.size());
}

void FreeRustRegexSetMatcher(void* matcher) {
    zeek_rust_regex_set_matcher_free(reinterpret_cast<ZeekRustRegexSetMatcher*>(matcher));
}

bool RustRegexSetMatcherMatchAny(const void* matcher, const uint8_t* data, size_t len) {
    return zeek_rust_regex_set_matcher_matches(reinterpret_cast<const ZeekRustRegexSetMatcher*>(matcher), data, len,
                                               nullptr, 0) != 0;
}

void RustRegexSetMatcherAppendMatches(const void* matcher, const uint8_t* data, size_t len, std::vector<int>& matches) {
    auto* rust_matcher = reinterpret_cast<const ZeekRustRegexSetMatcher*>(matcher);
    const auto count = zeek_rust_regex_set_matcher_pattern_len(rust_matcher);

    if ( count == 0 )
        return;

    std::vector<std::intptr_t> ids(count);
    const auto matched = zeek_rust_regex_set_matcher_matches(rust_matcher, data, len, ids.data(), ids.size());

    for ( size_t i = 0; i < std::min(matched, ids.size()); ++i )
        matches.push_back(static_cast<int>(ids[i]));
}

void* CompileRustRegexStreamMatcher(const std::vector<const char*>& patterns, const std::vector<std::intptr_t>& ids,
                                    bool dot_matches_new_line, size_t cache_capacity) {
    if ( patterns.empty() || patterns.size() != ids.size() )
        return nullptr;

    return zeek_rust_regex_stream_matcher_compile(patterns.data(), ids.data(), patterns.size(), dot_matches_new_line,
                                                  cache_capacity);
}

void FreeRustRegexStreamMatcher(void* matcher) {
    zeek_rust_regex_stream_matcher_free(reinterpret_cast<ZeekRustRegexStreamMatcher*>(matcher));
}

void* CreateRustRegexStreamState(const void* matcher) {
    return zeek_rust_regex_stream_state_create(reinterpret_cast<const ZeekRustRegexStreamMatcher*>(matcher));
}

void FreeRustRegexStreamState(void* state) {
    zeek_rust_regex_stream_state_free(reinterpret_cast<ZeekRustRegexStreamState*>(state));
}

void RustRegexStreamStateAppendMatches(const void* matcher, void* state, const uint8_t* data, size_t len, bool bol,
                                       bool eol, bool suppress_initial_empty_visible_match,
                                       std::vector<std::pair<int, uint64_t>>& matches) {
    auto* rust_matcher = reinterpret_cast<const ZeekRustRegexStreamMatcher*>(matcher);
    auto* rust_state = reinterpret_cast<ZeekRustRegexStreamState*>(state);
    const auto count = zeek_rust_regex_stream_matcher_pattern_len(rust_matcher);

    if ( count == 0 )
        return;

    std::vector<std::intptr_t> ids(count);
    std::vector<uint64_t> positions(count);
    const auto matched = zeek_rust_regex_stream_state_match(
        rust_matcher, rust_state, data, len, bol, eol, suppress_initial_empty_visible_match, ids.data(),
        positions.data(), ids.size());

    for ( size_t i = 0; i < std::min({matched, ids.size(), positions.size()}); ++i )
        matches.emplace_back(static_cast<int>(ids[i]), positions[i]);
}

} // namespace zeek::detail
